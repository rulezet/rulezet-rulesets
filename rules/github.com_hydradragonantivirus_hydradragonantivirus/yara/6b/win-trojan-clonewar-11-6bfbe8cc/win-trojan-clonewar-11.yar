rule Win_Trojan_Clonewar_11
{
strings:
	$a0 = { ba1a01b90000b43ccd21725d8bd8b9fc00ba0001b440cd21b43ecd21ba1a01b90300b80143cd21 }


condition:
	$a0
}