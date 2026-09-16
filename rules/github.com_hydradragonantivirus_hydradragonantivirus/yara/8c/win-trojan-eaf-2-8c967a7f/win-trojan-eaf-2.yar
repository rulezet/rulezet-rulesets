rule Win_Trojan_EAF_2
{
strings:
	$a0 = { 5e81ee03008d94e901b41acd21e8a901e83e007510e8a2008d940702c684140224b409cd21b41aba8000cd21fc }


condition:
	$a0
}