import "pe"
rule _PE_Admin_V10_EncryptPE_V12003518_Sold__Flying_Cat_
{
	meta:
		description = "PE_Admin V1.0 (EncryptPE V1.2003.5.18 Sold) -> Flying Cat"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}