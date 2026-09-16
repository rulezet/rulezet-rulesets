import "pe"
rule shrinkwrap14
{
	meta:
		author = "PEiD"
		description = "ShrinkWrap 1.4 -> snyper"
		group = "173"
		function = "0"
	strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }
	condition:
		$a0 at pe.entry_point
}