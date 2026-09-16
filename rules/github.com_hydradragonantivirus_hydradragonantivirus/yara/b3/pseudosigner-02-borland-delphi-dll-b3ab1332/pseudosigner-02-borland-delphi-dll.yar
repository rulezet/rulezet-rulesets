import "pe"
rule _PseudoSigner_02_Borland_Delphi_DLL_
{
	meta:
		description = "PseudoSigner 0.2 [Borland Delphi DLL"
	strings:
		$0 = {55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00}
	condition:
		$0 at pe.entry_point
}