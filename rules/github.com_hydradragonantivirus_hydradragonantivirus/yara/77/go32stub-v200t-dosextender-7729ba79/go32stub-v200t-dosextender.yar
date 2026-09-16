import "pe"
rule _Go32Stub_v200T_DOSExtender_
{
	meta:
		description = "Go32Stub v.2.00T DOS-Extender"
	strings:
		$0 = {0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 3C}
	condition:
		$0 at pe.entry_point
}