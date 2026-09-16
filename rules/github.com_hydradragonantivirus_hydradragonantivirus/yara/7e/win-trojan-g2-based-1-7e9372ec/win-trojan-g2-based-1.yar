rule Win_Trojan_G2_based_1
{
strings:
	$a0 = { 8d96a70259cd21b8024233c999cd21b4408d960001b97d01cd21b80157 }


condition:
	$a0
}