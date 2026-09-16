import "hash"
rule macho_entitlehash_check
{
	meta:
		description = "Identify a specific entitlehash"
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.05"
		DaysofYARA = "36/100"

	strings:
		$cs_magic = { fa de 0c 00 } private
		$cs_magic_entitlement = { fa de 71 71 } private

	condition:
		(
			uint32(0) == 0xfeedface or 			uint32(0) == 0xcefaedfe or 			uint32(0) == 0xfeedfacf or 			uint32(0) == 0xcffaedfe or 			uint32(0) == 0xcafebabe or 			uint32(0) == 0xbebafeca    		) and
		all of them and
		for any i in (1 .. #cs_magic_entitlement) : (
			hash.md5(
				@cs_magic_entitlement[i] + 8,
				@cs_magic_entitlement[i] + uint32be(@cs_magic_entitlement[i] + 4)
			) == "7332589bceacb1d5553a77903020d63f"

		)
}