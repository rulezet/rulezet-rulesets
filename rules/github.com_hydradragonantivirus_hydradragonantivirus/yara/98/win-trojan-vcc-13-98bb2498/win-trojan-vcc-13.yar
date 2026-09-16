rule Win_Trojan_VCC_13
{
strings:
	$a0 = { b440b966018d960601cd21e80500b43ecd21c38db62001b92701803400464975f9c3 }


condition:
	$a0
}