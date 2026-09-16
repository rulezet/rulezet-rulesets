rule pec2_BoB
{
	meta:
		author = "PEiD"
		description = "PECompact 2.xx -> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }
	condition:
		$a0
}