rule Win_Trojan_Corp_1
{
strings:
	$a0 = { b440b959028d960600cd21e80500b43ecd21c38db61f00b91b02803400464975f9c3 }


condition:
	$a0
}