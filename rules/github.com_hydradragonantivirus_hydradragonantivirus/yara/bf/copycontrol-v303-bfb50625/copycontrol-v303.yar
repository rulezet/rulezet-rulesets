import "pe"
rule _CopyControl_v303_
{
	meta:
		description = "CopyControl v3.03"
	strings:
		$0 = {55 8B EC 81 EC 20 02 ?? ?? 53 56 57 6A ?? FF 15 18 61 40 ?? 68 ?? 70 40 ?? 89 45 08 FF 15 14 61 40 ?? 85 C0 74 27 6A ?? A1 ?? 20 40 ?? 50 FF 15 3C 61 40 ?? 8B F0 6A 06 56 FF 15 38 61 40 ??}
	condition:
		$0 at pe.entry_point
}