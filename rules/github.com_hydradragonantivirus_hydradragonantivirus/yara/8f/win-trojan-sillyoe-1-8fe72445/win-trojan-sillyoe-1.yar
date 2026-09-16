rule Win_Trojan_SillyOE_1
{
strings:
	$a0 = { bf9e00b000b90c00f2aec60500b43db001cd2189c3b440ba0001b91001cd21b43ecd21b001 }


condition:
	$a0
}