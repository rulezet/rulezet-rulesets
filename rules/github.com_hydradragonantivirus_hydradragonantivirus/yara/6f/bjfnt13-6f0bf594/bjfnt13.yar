import "pe"
rule bjfnt13
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.3 -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }
	condition:
		$a0 at pe.entry_point
}