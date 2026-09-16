rule Win_Trojan_Clonewar_13
{
strings:
	$a0 = { 21725193b9ff00ba0001b440cd21b43ecd21b80143ba4401b90300cd21c3bc0c048bdcb104 }


condition:
	$a0
}