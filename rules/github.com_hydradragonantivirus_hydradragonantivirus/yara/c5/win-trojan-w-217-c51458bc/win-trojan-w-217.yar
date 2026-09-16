rule Win_Trojan_W_217
{
strings:
	$a0 = { 55e800000000585affe4 }


condition:
	$a0
}