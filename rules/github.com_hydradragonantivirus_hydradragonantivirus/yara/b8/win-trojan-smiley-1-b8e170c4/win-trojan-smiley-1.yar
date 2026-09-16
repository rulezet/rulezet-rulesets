rule Win_Trojan_Smiley_1
{
strings:
	$a0 = { bf0790ba0001b440cd21a035073c00 }


condition:
	$a0
}