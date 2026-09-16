rule Win_Trojan_PS_MPC_1
{
strings:
	$a0 = { a5c6865d0403b41a8d963204cd21b447b2008db6 }


condition:
	$a0
}