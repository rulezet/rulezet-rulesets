rule Win_Trojan_HH_8
{
strings:
	$a0 = { b440b99e018d960601cd21e80500b43ecd21c38db61f01b96001803435464975f9c3 }


condition:
	$a0
}