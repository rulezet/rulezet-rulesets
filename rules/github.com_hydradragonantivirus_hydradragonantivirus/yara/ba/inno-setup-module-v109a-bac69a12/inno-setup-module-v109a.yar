import "pe"
rule _Inno_Setup_Module_v109a_
{
	meta:
		description = "Inno Setup Module v1.09a"
	strings:
		$0 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8}
	condition:
		$0 at pe.entry_point
}