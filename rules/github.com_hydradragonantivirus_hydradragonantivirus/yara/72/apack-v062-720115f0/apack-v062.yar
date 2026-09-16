import "pe"
rule _aPack_v062_
{
	meta:
		description = "aPack v0.62"
	strings:
		$0 = {1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6}
	condition:
		$0 at pe.entry_point
}