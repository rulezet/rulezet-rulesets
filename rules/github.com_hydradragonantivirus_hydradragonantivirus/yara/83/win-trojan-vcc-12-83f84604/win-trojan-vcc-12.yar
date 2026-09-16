rule Win_Trojan_VCC_12
{
strings:
	$a0 = { b440b966018d960600cd21e80500b43ecd21c38db62000b92701803400464975f9c3 }


condition:
	$a0
}