rule realbasicold
{
	meta:
		author = "PEiD"
		description = "REALBasic"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 C0 A0 4B 00 64 FF 35 00 00 00 00 64 89 25 00 00 }
	condition:
		$a0
}