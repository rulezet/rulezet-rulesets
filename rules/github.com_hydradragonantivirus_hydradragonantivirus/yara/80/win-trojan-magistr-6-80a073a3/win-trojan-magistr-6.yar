rule Win_Trojan_Magistr_6
{
strings:
	$a0 = { ff360000646789260000b800000000 }


condition:
	$a0
}