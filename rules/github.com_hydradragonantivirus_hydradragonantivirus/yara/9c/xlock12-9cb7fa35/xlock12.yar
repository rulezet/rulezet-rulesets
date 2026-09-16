import "pe"
rule xlock12
{
	meta:
		author = "PEiD"
		description = "XCR 0.12 -> X-Lock"
		group = "192"
		function = "0"
	strings:
		$a0 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }
	condition:
		$a0 at pe.entry_point
}