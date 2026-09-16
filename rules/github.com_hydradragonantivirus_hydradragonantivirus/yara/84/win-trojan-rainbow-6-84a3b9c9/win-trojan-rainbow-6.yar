rule Win_Trojan_Rainbow_6
{
strings:
	$a0 = { e800005e83ee03b8ad1bcd133dedde75450e1f81c6640781 }


condition:
	$a0
}