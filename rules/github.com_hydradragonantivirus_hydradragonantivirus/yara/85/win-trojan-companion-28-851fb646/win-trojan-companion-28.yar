rule Win_Trojan_Companion_28
{
strings:
	$a0 = { 01b90000b43ccd21725d8bd8b99903ba0001b440cd21b43ecd21ba1a01b90300b80143cd21c3 }


condition:
	$a0
}