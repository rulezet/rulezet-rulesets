rule Win_Trojan_Miras_2
{
strings:
	$a0 = { 002d2923322f332f2634[2]6e232f2d00 }


condition:
	$a0
}