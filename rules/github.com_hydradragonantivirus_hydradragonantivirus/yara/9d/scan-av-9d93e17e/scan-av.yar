import "pe"
rule _SCAN_AV_
{
	meta:
		description = "SCAN /AV"
	strings:
		$0 = {1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72}
	condition:
		$0 at pe.entry_point
}