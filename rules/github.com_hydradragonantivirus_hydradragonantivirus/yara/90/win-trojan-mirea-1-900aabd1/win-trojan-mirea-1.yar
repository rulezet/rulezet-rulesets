rule Win_Trojan_Mirea_1
{
strings:
	$a0 = { ff2de23cdfc0b0e27ddfc02fe2bedfc06aa2fdc5fdffa2 }


condition:
	$a0
}