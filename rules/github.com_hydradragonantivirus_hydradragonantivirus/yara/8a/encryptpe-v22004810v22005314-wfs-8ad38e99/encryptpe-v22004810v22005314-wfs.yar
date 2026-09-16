import "pe"
rule _EncryptPE_V22004810V22005314__WFS_
{
	meta:
		description = "EncryptPE V2.2004.8.10-V2.2005.3.14 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00}
	condition:
		$0 at pe.entry_point
}