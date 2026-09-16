rule Win_Trojan_Iksmas_2
{
strings:
	$a0 = { e819097d4de91908b62ecccccccc518d4c24042bc81bc0f7d023c88bc425 }

	$a1 = { 48454c4f2000000051554954 }


condition:
	$a0 and $a1
}