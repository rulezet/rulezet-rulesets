rule Win_Trojan_Clonewar_7
{
strings:
	$a0 = { a4c3ba1a0133c9b8003dcd21c3ba1a0133c9b43ccd21725193b9e500ba0001b440cd21b43ecd21 }


condition:
	$a0
}