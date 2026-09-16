rule Win_Trojan_SillyC_81
{
strings:
	$a0 = { b440b9bc008d960f00cd21e80500b43ecd21c38db61a00b98d008034 }


condition:
	$a0
}