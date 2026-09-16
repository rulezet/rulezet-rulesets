rule Win_Trojan_Pixel_2
{
strings:
	$a0 = { fa01725dbaf901b409cd21b405b202 }


condition:
	$a0
}