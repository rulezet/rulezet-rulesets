rule Win_Trojan_Gpcode_3
{
strings:
	$a0 = { 5e7d667d2840194d17471b520c52????04 }


condition:
	$a0
}