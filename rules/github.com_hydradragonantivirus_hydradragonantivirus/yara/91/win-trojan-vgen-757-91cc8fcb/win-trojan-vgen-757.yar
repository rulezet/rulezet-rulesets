rule Win_Trojan_VGEN_757
{
strings:
	$a0 = { 1f07e800005d81ed0701b44e8d969c01b90000cd21b43db002ba9e00cd21505b53b43fb903008d969301cd21b800 }


condition:
	$a0
}