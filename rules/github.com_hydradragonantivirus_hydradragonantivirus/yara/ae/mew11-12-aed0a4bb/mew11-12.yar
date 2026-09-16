import "pe"
rule mew11_12
{
	meta:
		author = "PEiD"
		description = "MEW 11 SE 1.2 -> NorthFox/HCC"
		group = "555"
		function = "0"
	strings:
		$a0 = { 8B DE AD AD 50 AD 97 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 21 B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3E AA EB E0 E8 }
	condition:
		$a0 at pe.entry_point
}