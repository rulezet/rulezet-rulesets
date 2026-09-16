rule Win_Trojan_PS_MPC_4
{
strings:
	$a0 = { 01b837012e8135000047474875f6 }


condition:
	$a0
}