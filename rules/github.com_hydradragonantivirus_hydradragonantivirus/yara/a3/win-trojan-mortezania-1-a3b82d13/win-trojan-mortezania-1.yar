rule Win_Trojan_Mortezania_1
{
strings:
	$a0 = { c0b87d02bb1300268907b8409f8ec0bb0001b80602b90300ba8000cd1333c08ed8be4c00b8409f }


condition:
	$a0
}