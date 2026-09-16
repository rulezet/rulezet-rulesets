rule Win_Trojan_Cascade_4
{
strings:
	$a0 = { e800005b4b81eb30012ef6872b010174148daf5301555e2e8bbfff02b94c05313c464fe2fa }


condition:
	$a0
}