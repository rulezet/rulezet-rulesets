rule Win_Trojan_Corp_5
{
strings:
	$a0 = { b440b987028d960600cd21e80500b43ecd21c38db61f00b94902803400464975f9c3 }


condition:
	$a0
}