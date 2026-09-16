import "pe"
rule USSR0_31_bySpirit
{
	meta:
		author = "PEiD"
		description = "USSR 0.31 - by Spirit"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }
	condition:
		$a0 at pe.entry_point
}