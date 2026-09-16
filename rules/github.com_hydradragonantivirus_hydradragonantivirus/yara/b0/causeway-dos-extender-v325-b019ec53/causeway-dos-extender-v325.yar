import "pe"
rule _CauseWay_DOS_Extender_v325_
{
	meta:
		description = "CauseWay DOS Extender v3.25"
	strings:
		$0 = {FA 16 1F 26 ?? ?? ?? 83 ?? ?? 8E D0 FB 06 16 07 BE ?? ?? 8B FE B9 ?? ?? F3 A4 07}
	condition:
		$0 at pe.entry_point
}