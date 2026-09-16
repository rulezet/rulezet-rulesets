rule Win_Trojan_HH_7
{
strings:
	$a0 = { b440b96d018d960601cd21e80500b43ecd21c38db61f01b92f01803452464975f9c3 }


condition:
	$a0
}