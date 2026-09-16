rule Win_Trojan_Blava_1
{
strings:
	$a0 = { 9d81f9fefa751081fafafe750afa9c2eff1e9e00b9eeee }


condition:
	$a0
}