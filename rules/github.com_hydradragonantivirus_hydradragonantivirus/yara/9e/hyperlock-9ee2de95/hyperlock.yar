rule hyperlock
{
	meta:
		author = "PEiD"
		description = "Hyper Lock -> Guven Bilgisayar Ltd."
		group = "124"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 02 00 00 EB 59 5B E8 00 00 00 00 5F 81 EF 06 00 00 00 33 C0 8B F1 D1 E9 D1 E9 49 55 51 83 EE 04 D1 C2 31 14 33 03 04 33 33 D0 59 8B EC 03 55 FC E8 00 00 00 00 5D }
	condition:
		$a0
}