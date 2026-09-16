rule Win_Trojan_Cruel_3
{
strings:
	$a0 = { 40b90004ba0000e8490072043bc1740726804d0540eb1126c745150000b440b90400baf303e82b }


condition:
	$a0
}