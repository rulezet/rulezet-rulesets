rule NeoLitevXX : NeoworxInc
{
	meta:
		author="_pusher_"
		date = "2016-02"
	strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 5C 02 00 00 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 02 FF E0 8B E5 5D C2 0C 00 }
	condition:
		$a0
}