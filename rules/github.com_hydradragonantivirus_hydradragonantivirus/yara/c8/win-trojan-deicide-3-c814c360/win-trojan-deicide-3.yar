rule Win_Trojan_Deicide_3
{
strings:
	$a0 = { de9c505351521e06165657a1d00aa3cc0a8b1ed20a }


condition:
	$a0
}