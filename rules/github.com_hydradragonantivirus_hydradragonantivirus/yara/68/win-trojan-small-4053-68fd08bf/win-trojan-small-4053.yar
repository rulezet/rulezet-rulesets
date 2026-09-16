rule Win_Trojan_Small_4053
{
strings:
	$a0 = { 575553e864000000e81500000085c975f789f82d345e341205785634125b5d5f }


condition:
	$a0
}