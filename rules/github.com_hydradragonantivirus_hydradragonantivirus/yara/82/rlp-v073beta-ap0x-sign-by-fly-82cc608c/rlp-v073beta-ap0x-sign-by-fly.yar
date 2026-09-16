rule _RLP_V073beta__ap0x__Sign_by_fly_
{
	meta:
		description = "RLP V0.7.3.beta -> ap0x ! Sign by fly"
	strings:
		$0 = {2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0}
	condition:
		$0
}