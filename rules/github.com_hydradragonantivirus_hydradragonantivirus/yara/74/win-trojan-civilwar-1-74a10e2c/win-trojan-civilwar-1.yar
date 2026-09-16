rule Win_Trojan_Civilwar_1
{
strings:
	$a0 = { fe2d030089862f02b80042e86b00b440b901008d963102cd21b440b902008d962f02cd21b440 }


condition:
	$a0
}