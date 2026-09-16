rule Win_Trojan_Qres_1
{
strings:
	$a0 = { a37f00b440b9080133d2cd21b8004233c933d2cd21b440b90500ba7e00cd21b43ecd21eb00 }


condition:
	$a0
}