rule Win_Trojan_B_89
{
strings:
	$a0 = { 0b02f3a4bfbe01bebe03b94300f3a44133dbb8010332f6e861ffc3 }


condition:
	$a0
}