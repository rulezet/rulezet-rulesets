rule Win_Trojan_Companion_21
{
strings:
	$a0 = { abcd278d7f4089d6601e57803c2ea475fac704434fb84558ab98ab5fb456cd21b43cb9003ecd }


condition:
	$a0
}