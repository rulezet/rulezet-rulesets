rule Win_Trojan_Jabberwocky_1
{
strings:
	$a0 = { 108ec0be0000bf0000b9fffff3a41e0789d6bf0001b9 }


condition:
	$a0
}