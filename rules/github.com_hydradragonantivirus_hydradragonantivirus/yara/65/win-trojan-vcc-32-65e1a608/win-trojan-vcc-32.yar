rule Win_Trojan_VCC_32
{
strings:
	$a0 = { b440b9e8028d960600cd21e80500b43ecd21c38db61100b9b802803400464975f9c3 }


condition:
	$a0
}