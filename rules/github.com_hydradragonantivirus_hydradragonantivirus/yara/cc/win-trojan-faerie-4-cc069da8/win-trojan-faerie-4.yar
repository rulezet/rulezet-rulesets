rule Win_Trojan_Faerie_4
{
strings:
	$a0 = { d233c9b80242cd212d03008986040189860f028d96 }


condition:
	$a0
}