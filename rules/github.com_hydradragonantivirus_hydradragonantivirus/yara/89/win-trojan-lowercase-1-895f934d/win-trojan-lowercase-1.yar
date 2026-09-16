rule Win_Trojan_Lowercase_1
{
strings:
	$a0 = { e86f02c3e85300e8b102721ee86a0272 }


condition:
	$a0
}