rule Win_Trojan_Rainbow_4
{
strings:
	$a0 = { ad1bcd133dedde75460e1f81c6a307813c4d5a7409bf00 }


condition:
	$a0
}