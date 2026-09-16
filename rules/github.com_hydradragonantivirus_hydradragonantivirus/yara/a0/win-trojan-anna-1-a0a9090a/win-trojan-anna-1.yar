rule Win_Trojan_Anna_1
{
strings:
	$a0 = { b4408b9c3504b9e6028d940e01cd21e8d6ffe8be }


condition:
	$a0
}