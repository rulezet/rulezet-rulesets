rule Win_Trojan_Corp_3
{
strings:
	$a0 = { b440b982028d960600cd21e80500b43ecd21c38db61f00b94402803400464975f9c3 }


condition:
	$a0
}