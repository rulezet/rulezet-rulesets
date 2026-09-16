import "pe"
rule _EXEPACK_LINK_v360_v364_v365_or_50121_
{
	meta:
		description = "EXEPACK (LINK) v3.60, v3.64, v3.65 or 5.01.21"
	strings:
		$0 = {8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB}
	condition:
		$0 at pe.entry_point
}