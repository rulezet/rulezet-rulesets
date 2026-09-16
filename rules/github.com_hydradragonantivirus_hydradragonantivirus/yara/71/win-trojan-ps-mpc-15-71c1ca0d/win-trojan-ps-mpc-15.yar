rule Win_Trojan_PS_MPC_15
{
strings:
	$a0 = { be1300bf58012e812c0b2446464f75f6 }


condition:
	$a0
}