rule Win_Trojan_Yosha_7
{
strings:
	$a0 = { 12e80b00268a1db81612e80200 }


condition:
	$a0
}