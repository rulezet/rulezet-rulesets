rule Win_Trojan_Thespian_5
{
strings:
	$a0 = { b440b9ed018d960600cd21e80500b43ecd21c38db61100b9bd01803400464975f9c3 }


condition:
	$a0
}