import "pe"
rule _WinRAR_SFX_
{
	meta:
		description = "WinRAR SFX"
	strings:
		$0 = {E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00}
	condition:
		$0 at pe.entry_point
}