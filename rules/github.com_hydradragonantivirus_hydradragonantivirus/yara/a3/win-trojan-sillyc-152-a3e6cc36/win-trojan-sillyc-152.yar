rule Win_Trojan_SillyC_152
{
strings:
	$a0 = { e93e88861102b440b903008d961102cd21b8024233c92bd23e8b9e0b02cd21b440b91401903e8b }


condition:
	$a0
}