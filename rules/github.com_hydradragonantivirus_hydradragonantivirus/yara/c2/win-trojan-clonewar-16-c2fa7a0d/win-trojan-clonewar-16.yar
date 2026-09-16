rule Win_Trojan_Clonewar_16
{
strings:
	$a0 = { 21725193b90b01ba0001b440cd21b43ecd21b80143ba4401b90300cd21c3bc18048bdcb104 }


condition:
	$a0
}