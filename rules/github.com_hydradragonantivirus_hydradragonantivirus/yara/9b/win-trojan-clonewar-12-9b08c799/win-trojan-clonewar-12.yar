rule Win_Trojan_Clonewar_12
{
strings:
	$a0 = { 3ccd21725193b9fc00ba0001b440cd21b43ecd21ba3e01b90300b80143cd21c3bc09048bdcb104 }


condition:
	$a0
}