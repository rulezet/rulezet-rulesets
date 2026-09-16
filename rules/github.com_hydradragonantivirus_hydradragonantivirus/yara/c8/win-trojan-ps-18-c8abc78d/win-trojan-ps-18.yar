rule Win_Trojan_PS_18
{
strings:
	$a0 = { 060001b800c60602014ce800005d83c51089eeb900042e80340846e2f9 }


condition:
	$a0
}