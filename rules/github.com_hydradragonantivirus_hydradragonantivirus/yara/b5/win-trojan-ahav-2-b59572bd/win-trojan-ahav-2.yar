rule Win_Trojan_Ahav_2
{
strings:
	$a0 = { 02b440b97b018d960001cd21b8004233c933d2cd21 }


condition:
	$a0
}