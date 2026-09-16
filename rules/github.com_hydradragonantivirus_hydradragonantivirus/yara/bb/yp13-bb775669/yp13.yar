rule yp13
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.3 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 ?? B9 5D 34 40 ?? 81 E9 C6 28 40 ?? 8B D5 81 C2 C6 28 40 ?? 8D 3A 8B F7 33 C0 EB 04 90 EB 01 }
	condition:
		$a0
}