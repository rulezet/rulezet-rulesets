rule Win_Trojan_Horse_11
{
strings:
	$a0 = { 8c08be5401fcac30c3e2fb881e3801 }


condition:
	$a0
}