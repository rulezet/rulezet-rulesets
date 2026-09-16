import "pe"
rule _VcAsm_Protector_V10X_VcAsm_
{
	meta:
		description = "VcAsm Protector V1.0X-> VcAsm"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00}
	condition:
		$0 at pe.entry_point
}