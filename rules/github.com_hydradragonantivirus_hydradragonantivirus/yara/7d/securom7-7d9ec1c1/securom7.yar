import "pe"
rule securom7
{
	meta:
		author = "PEiD"
		description = "SecuROM 7.x.x.x -> Sony DADC"
		group = "666"
		function = "0"
	strings:
		$a0 = { 53 65 63 75 52 4F 4D 20 55 73 65 72 20 41 63 63 65 73 73 20 53 65 72 76 69 63 65 20 28 56 37 29 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}