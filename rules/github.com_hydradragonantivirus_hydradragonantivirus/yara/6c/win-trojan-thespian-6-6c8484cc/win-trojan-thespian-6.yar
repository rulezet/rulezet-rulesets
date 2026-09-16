rule Win_Trojan_Thespian_6
{
strings:
	$a0 = { b440b952028d960600cd21e80500b43ecd21c38db61100b92202803400464975f9c3 }


condition:
	$a0
}