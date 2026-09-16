rule Win_Trojan_Burn_1
{
strings:
	$a0 = { 0300eb7f908a261602b9cc00be1b018bfeac9032c4aa90e2f8c3 }


condition:
	$a0
}