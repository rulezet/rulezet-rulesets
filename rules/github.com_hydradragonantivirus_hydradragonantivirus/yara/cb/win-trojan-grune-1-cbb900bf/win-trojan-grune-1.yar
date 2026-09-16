rule Win_Trojan_Grune_1
{
strings:
	$a0 = { c60600004d5e5681c6d50483c36053078bfefdb9 }


condition:
	$a0
}