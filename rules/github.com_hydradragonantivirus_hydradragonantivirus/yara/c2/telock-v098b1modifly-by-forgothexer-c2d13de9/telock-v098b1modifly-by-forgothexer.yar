import "pe"
rule _TElock_v098b1Modifly_by_forgothexer_
{
	meta:
		description = "TElock v0.98b1<->Modifly by forgot/hexer"
	strings:
		$0 = {9C 6A 03 73 0B EB 02 75 75}
	condition:
		$0 at pe.entry_point
}