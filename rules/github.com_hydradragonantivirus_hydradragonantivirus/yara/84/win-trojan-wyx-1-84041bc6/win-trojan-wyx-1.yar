rule Win_Trojan_WYX_1
{
strings:
	$a0 = { b419a0787cb72bbe747cb34db90b01b66f280446b291e2f9 }


condition:
	$a0
}