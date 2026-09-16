rule Win_Trojan_Clonewar_4
{
strings:
	$a0 = { bade0133c9b8003dcd21c3bade0133c9b43ccd2172538bd8b9cf00ba0001b440cd21b43ecd21 }


condition:
	$a0
}