rule Win_Trojan_Erasembr_1
{
strings:
	$a0 = { b8010333dbb90100ba8000cd13 }


condition:
	$a0
}