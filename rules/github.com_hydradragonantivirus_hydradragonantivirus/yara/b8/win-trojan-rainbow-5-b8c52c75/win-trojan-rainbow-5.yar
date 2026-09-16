rule Win_Trojan_Rainbow_5
{
strings:
	$a0 = { ad1bcd133dedde75450e1f81c6fb07813c4d5a7409bf00 }


condition:
	$a0
}