rule Win_Trojan_Bumblebee_2
{
strings:
	$a0 = { 01010055a601000000ffff000000008a040000070000007408 }


condition:
	$a0
}