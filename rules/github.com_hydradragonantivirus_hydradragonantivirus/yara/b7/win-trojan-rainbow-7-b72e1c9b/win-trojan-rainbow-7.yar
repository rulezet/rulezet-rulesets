rule Win_Trojan_Rainbow_7
{
strings:
	$a0 = { 1bcd133dedde75450e1f81c69e07813c4d5a7409bf00 }


condition:
	$a0
}