import "pe"
rule Themida_WinLicense1_X__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.X -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 43 4F 4D 43 54 4C 33 32 2E 64 6C 6C 00 00 00 49 6E 69 74 43 6F 6D 6D 6F 6E 43 6F 6E 74 72 6F 6C 73 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}