rule Win_Trojan_Minimal_3
{
strings:
	$a0 = { 01b92d00b440cd21b43e }


condition:
	$a0
}