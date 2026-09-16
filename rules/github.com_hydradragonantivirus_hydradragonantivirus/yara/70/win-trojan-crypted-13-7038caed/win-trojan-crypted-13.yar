rule Win_Trojan_Crypted_13
{
strings:
	$a0 = { eb065652554c5a00909090909090 }


condition:
	$a0
}