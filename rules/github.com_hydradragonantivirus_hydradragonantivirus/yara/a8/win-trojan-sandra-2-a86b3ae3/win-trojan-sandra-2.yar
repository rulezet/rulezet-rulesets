rule Win_Trojan_Sandra_2
{
strings:
	$a0 = { 6601fafa8a279032260901908827fa8a67029032260a01f8886702f983c304fb81fb7708 }


condition:
	$a0
}