rule Win_Trojan_Fakeav_12
{
strings:
	$a0 = { 726c74488d0d64bf240281e90abb24 }

	$a1 = { 416e742d69766972757320506c7573 }


condition:
	$a0 and $a1
}