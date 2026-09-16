rule fsg133
{
	meta:
		author = "PEiD"
		description = "FSG 1.33 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C }
	condition:
		$a0
}