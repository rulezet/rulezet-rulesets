rule Win_Trojan_DRap20_1
{
strings:
	$a0 = { fc3d696974ea80fc11723f80fc12773a2eff1e5d07 }


condition:
	$a0
}