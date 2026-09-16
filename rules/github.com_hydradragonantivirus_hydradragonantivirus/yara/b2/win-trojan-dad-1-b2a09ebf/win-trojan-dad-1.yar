rule Win_Trojan_Dad_1
{
strings:
	$a0 = { 01b440b9f7018d960001cd21b8004233c933d2cd21b8ff3fba0300428bca8d96dd0140cd21 }


condition:
	$a0
}