import "pe"
rule exesmash
{
	meta:
		author = "PEiD"
		description = "ExeSmasher"
		group = "116"
		function = "0"
	strings:
		$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }
	condition:
		$a0 at pe.entry_point
}