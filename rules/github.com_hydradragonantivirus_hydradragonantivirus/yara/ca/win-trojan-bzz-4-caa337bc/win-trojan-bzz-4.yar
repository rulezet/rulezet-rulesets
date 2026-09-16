rule Win_Trojan_Bzz_4
{
strings:
	$a0 = { 2193b440b903008d96db02cd21b002b44233c999cd21b93200be00008dbe0903f3a48bd7be8205 }


condition:
	$a0
}