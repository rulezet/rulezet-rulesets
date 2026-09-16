rule Win_Trojan_SmanNumberOne_1
{
strings:
	$a0 = { 041e57bf00010e57b8fb2eb90700d3e840e817fce8abe0bf0d041ee890fae8a1e0e8d4f5bfca }


condition:
	$a0
}