rule Win_Trojan_Minimal_2
{
strings:
	$a0 = { b440ba0001b12dcd21b43e }


condition:
	$a0
}