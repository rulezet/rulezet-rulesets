rule Win_Trojan_Shell_1
{
strings:
	$a0 = { 0f823e01b440b96429ba00001e0e1fcd21 }


condition:
	$a0
}