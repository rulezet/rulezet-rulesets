rule Win_Trojan_Halley_1
{
strings:
	$a0 = { 2a2e657865042e636f6d005589e5b800019a7c02 }


condition:
	$a0
}