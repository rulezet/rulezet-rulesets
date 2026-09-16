rule Win_Trojan_Alert_1
{
strings:
	$a0 = { b440b9e0028d960600cd21e80500b43ecd21c38db61700b9aa02803400464975f9c3 }


condition:
	$a0
}