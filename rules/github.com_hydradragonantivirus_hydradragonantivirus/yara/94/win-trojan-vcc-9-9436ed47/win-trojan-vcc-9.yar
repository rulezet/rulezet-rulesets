rule Win_Trojan_VCC_9
{
strings:
	$a0 = { 4e018d960600cd21e80500b43ecd21c38db61f00b9 }


condition:
	$a0
}