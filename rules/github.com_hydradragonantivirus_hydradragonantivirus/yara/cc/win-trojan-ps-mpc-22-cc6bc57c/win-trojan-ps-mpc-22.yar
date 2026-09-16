rule Win_Trojan_PS_MPC_22
{
strings:
	$a0 = { 5b4d50435d }

	$a1 = { b44eb90700cd2172 }

	$a2 = { 2a2e657865002a2e636f6d00 }


condition:
	$a0 and $a1 and $a2
}