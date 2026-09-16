rule Win_Trojan_Zed_1
{
strings:
	$a0 = { ff01b440b91f01ba2802cd217213b8004233c933d2cd21b440b91f01ba0001cd21b43ecd211f07 }


condition:
	$a0
}