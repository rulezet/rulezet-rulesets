import "pe"
rule _EncryptPE_V22004616V22006630__WFS__Sign_by_fly_
{
	meta:
		description = "EncryptPE V2.2004.6.16-V2.2006.6.30 -> WFS ! Sign by fly"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}