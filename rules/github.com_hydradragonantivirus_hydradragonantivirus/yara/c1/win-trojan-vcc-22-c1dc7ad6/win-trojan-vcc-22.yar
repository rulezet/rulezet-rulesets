rule Win_Trojan_VCC_22
{
strings:
	$a0 = { b440b9b4018d960600cd21e80500b43ecd21c38db61100b9840180345e464975f9c3 }


condition:
	$a0
}