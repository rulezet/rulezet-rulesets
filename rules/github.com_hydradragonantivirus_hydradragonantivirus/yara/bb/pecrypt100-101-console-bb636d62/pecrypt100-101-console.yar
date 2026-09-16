import "pe"
rule pecrypt100_101_console
{
	meta:
		author = "PEiD"
		description = "PE Crypt 1.00/1.01/Console -> random, killa & acpizer"
		group = "140"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
	condition:
		$a0 at pe.entry_point
}