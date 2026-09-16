rule Win_Trojan_Waledac_30
{
strings:
	$a0 = { 558bec21c381c1bb3a00008d5a6381e8051200008d79 }


condition:
	$a0
}