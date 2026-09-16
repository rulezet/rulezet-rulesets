rule Win_Trojan_Cruel_1
{
strings:
	$a0 = { 40b9fe03ba0000e8490072043bc1740726804d0540eb1126c745150000b440b90400baf103e82b }


condition:
	$a0
}