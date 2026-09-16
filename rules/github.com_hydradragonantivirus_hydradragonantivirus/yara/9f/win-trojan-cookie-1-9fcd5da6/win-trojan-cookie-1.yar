rule Win_Trojan_Cookie_1
{
strings:
	$a0 = { e23e1e57bf48201e57b8c01c50bf663f1e579a8209d100 }


condition:
	$a0
}