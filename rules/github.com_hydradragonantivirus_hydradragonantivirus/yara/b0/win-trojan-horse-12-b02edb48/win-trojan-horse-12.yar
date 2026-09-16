rule Win_Trojan_Horse_12
{
strings:
	$a0 = { f8b8534bcd2172151e0e1f8bf783ee03 }


condition:
	$a0
}