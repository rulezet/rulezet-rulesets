rule Win_Trojan_Shake_2
{
strings:
	$a0 = { b80342cd213d34127503eb4890b44abb }


condition:
	$a0
}