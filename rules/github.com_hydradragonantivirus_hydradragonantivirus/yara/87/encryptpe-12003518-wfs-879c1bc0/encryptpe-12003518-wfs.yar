import "pe"
rule _EncryptPE_12003518__WFS_
{
	meta:
		description = "EncryptPE 1.2003.5.18 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 79}
	condition:
		$0 at pe.entry_point
}