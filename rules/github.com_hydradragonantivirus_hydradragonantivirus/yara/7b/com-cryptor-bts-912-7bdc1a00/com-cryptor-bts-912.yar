import "pe"
rule _Com_Cryptor_BTS_912_
{
	meta:
		description = "Com Cryptor BTS 9.12"
	strings:
		$0 = {B7 00 E8 05 00 83 ED 02 EB 03 5D 55 C3 BF 1A 00 03 FD 8B F7 B9 71 02 AC 02 C7 AA E2 FA}
	condition:
		$0 at pe.entry_point
}