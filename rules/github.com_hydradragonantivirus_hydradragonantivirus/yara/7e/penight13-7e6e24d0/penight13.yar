import "pe"
rule penight13
{
	meta:
		author = "PEiD"
		description = "PENightMare 1.3 -> FreddyK"
		group = "150"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }
	condition:
		$a0 at pe.entry_point
}