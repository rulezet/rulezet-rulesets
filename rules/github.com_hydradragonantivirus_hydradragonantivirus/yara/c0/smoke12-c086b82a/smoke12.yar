import "pe"
rule smoke12
{
	meta:
		author = "PEiD"
		description = "SmokesCrypt 1.2 -> Smoke"
		group = "174"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
	condition:
		$a0 at pe.entry_point
}