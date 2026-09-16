rule Win_Trojan_Birgit_47
{
strings:
	$a0 = { 0166a00a013c00740c66300743??????????027ef4c3 }


condition:
	$a0
}