rule Win_Trojan_Corp_9
{
strings:
	$a0 = { b440b9b3028d960600cd21e80500b43ecd21c38db61f00b97502803400464975f9c3 }


condition:
	$a0
}