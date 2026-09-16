import "pe"
rule _aPack_v098b_DS__ES_not_saved_
{
	meta:
		description = "aPack v0.98b (DS & ES not saved)"
	strings:
		$0 = {8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75}
	condition:
		$0 at pe.entry_point
}