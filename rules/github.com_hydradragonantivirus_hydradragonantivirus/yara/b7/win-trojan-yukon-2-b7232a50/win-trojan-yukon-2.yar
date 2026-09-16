rule Win_Trojan_Yukon_2
{
strings:
	$a0 = { 01b43bcd21ba5c01b41acd218d16 }


condition:
	$a0
}