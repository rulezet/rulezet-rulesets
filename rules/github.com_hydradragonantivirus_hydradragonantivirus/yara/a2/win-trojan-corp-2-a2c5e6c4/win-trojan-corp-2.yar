rule Win_Trojan_Corp_2
{
strings:
	$a0 = { b440b95f028d960600cd21e80500b43ecd21c38db61f00b92102803400464975f9c3 }


condition:
	$a0
}