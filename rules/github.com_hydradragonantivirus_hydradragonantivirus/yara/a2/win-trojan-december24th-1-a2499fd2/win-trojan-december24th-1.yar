rule Win_Trojan_December24th_1
{
strings:
	$a0 = { 067e03feb45290cd212e8c06450326 }


condition:
	$a0
}