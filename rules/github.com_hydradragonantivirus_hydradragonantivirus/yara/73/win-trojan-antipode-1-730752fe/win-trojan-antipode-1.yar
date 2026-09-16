rule Win_Trojan_Antipode_1
{
strings:
	$a0 = { eb14be300003f28bfe81ef4001b9bf03313c46e2fb }


condition:
	$a0
}