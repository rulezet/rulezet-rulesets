import "pe"
rule e32pack136
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.36 -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }
	condition:
		$a0 at pe.entry_point
}