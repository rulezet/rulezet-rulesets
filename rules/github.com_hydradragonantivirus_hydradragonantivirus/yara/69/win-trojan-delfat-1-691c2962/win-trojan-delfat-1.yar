rule Win_Trojan_DelFat_1
{
strings:
	$a0 = { b002b90008ba0000cd26b44ccd210d0a }


condition:
	$a0
}