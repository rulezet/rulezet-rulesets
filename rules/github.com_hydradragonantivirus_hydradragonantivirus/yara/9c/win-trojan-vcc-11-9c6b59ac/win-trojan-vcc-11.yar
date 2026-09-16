rule Win_Trojan_VCC_11
{
strings:
	$a0 = { b440b965018d960600cd21e80500b43ecd21c38db61f00b92701803400464975f9c3 }


condition:
	$a0
}