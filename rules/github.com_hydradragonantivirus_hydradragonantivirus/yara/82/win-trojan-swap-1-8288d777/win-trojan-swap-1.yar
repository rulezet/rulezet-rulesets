rule Win_Trojan_Swap_1
{
strings:
	$a0 = { 31c0cd13b80202b90627ba0001bb0020 }


condition:
	$a0
}