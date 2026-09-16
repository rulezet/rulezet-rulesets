rule Win_Trojan_Flex_2
{
strings:
	$a0 = { b60b008bfeb9ca01ac340faae2fac35b464c45585d }


condition:
	$a0
}