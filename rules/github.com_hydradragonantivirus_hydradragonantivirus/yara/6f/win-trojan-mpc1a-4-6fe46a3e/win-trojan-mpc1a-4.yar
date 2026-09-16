rule Win_Trojan_MPC1a_4
{
strings:
	$a0 = { a5c686630503b41a8d963805cd21b447b2008db6 }


condition:
	$a0
}