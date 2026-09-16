import "pe"
rule fsg2
{
	meta:
		author = "PEiD"
		description = "FSG 2.0 -> bart/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 }
	condition:
		$a0 at pe.entry_point
}