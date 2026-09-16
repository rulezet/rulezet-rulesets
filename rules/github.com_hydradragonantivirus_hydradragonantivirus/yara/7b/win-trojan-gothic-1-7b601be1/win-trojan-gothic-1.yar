rule Win_Trojan_Gothic_1
{
strings:
	$a0 = { b9bf018d960600cd21e80500b43ecd21c38db62000b9 }


condition:
	$a0
}