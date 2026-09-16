rule Win_Trojan_Westwood_1
{
strings:
	$a0 = { 13000e1fc7061d00907eb80825ba1c02 }


condition:
	$a0
}