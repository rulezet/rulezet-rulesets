rule Win_Trojan_Khizhnjak_42
{
strings:
	$a0 = { b44e8d16????b92200cd21730eebdd8d16????b44fcd21 }


condition:
	$a0
}