rule Win_Trojan_Rainbow_9
{
strings:
	$a0 = { 1bcd133dedde75460e1f81c6a907813c4d5a7409bf00 }


condition:
	$a0
}