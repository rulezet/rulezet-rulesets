rule Win_Trojan_Darklord_2
{
strings:
	$a0 = { 8cc801060b0158ea000140 }


condition:
	$a0
}