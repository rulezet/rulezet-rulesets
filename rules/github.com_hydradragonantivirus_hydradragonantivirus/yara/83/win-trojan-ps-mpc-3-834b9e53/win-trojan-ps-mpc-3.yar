rule Win_Trojan_PS_MPC_3
{
strings:
	$a0 = { e90000bf1201b97e032e810500004747e2f7 }


condition:
	$a0
}