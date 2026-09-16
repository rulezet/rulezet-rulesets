rule packman11
{
	meta:
		author = "PEiD"
		description = "Packanoid 1.1 -> Arkanoid"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 64 00 40 00 50 50 8B 70 9E 8B 78 60 B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 }
	condition:
		$a0
}