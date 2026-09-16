rule Win_Trojan_Small_4093
{
strings:
	$a0 = { 7405e857000000eb3cc22000e839000000e877 }


condition:
	$a0
}