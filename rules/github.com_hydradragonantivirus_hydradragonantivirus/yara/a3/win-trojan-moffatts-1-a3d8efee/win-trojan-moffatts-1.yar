rule Win_Trojan_Moffatts_1
{
strings:
	$a0 = { a4e2fdba2d03ffd2c353ba1a03ffd25bb440b92d02ba0001cd2153ba1a03ffd25bc3 }


condition:
	$a0
}