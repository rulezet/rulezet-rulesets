rule Win_Trojan_MSK_1
{
strings:
	$a0 = { 01cd21ba9e00bf9e00b000b90c00f2aec60500b43db001cd2189c3b440ba0001b91c01cd21b4 }


condition:
	$a0
}