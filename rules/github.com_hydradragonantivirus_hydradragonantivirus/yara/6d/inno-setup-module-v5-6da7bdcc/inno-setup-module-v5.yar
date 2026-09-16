import "pe"
rule _Inno_Setup_Module_v5_
{
	meta:
		description = "Inno Setup Module v5"
	strings:
		$0 = {55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? F3 FF FF E8 ?? F4 FF FF 33 C0 55}
	condition:
		$0 at pe.entry_point
}