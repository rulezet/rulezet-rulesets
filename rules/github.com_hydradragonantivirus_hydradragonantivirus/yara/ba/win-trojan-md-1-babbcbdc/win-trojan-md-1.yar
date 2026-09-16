rule Win_Trojan_MD_1
{
strings:
	$a0 = { b440b9fa018d960600cd21e80500b43ecd21c38db62000b9bb01803400464975f9c3 }


condition:
	$a0
}