rule Win_Trojan_Xuxa_5
{
strings:
	$a0 = { 26803e6e00117508c6061e0201eb0690 }


condition:
	$a0
}