rule Win_Trojan_Clonewar_10
{
strings:
	$a0 = { d8b9f600ba0001b440cd21b43ecd21ba1a01b90300b801 }


condition:
	$a0
}