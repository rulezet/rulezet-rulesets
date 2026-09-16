rule Win_Trojan_PS_MPC_14
{
strings:
	$a0 = { e90000bb2a02be13012e8104000046464b75f6 }


condition:
	$a0
}