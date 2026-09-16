rule Win_Trojan_Clonewar_20
{
strings:
	$a0 = { 33c9b43ccd21723993b92502ba0001b440cd21b43ecd21ba5b02b90300b80143cd21e90600 }


condition:
	$a0
}