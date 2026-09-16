rule rlpack_115116_aplib_043
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15 - 1.16 (aPlib 0.43) -> ap0x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}