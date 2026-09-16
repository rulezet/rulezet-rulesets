rule estealth2
{
	meta:
		author = "PEiD"
		description = "EXEStealth 2.0 - 2.4 -> WebtoolMaster"
		group = "119"
		function = "7"
	strings:
		$a0 = { 60 BE 00 90 41 00 8D BE 00 80 FE FF 57 83 CD FF EB 10 }
	condition:
		$a0
}