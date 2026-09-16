rule Win_Trojan_Alabama_2
{
strings:
	$a0 = { c6730726c605cf4febf026ff0603 }


condition:
	$a0
}