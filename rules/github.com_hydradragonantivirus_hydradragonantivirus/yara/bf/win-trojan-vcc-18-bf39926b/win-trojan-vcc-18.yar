rule Win_Trojan_VCC_18
{
strings:
	$a0 = { b440b996018d960600cd21e80500b43ecd21c38db61f00b95801803400464975f9c3 }


condition:
	$a0
}