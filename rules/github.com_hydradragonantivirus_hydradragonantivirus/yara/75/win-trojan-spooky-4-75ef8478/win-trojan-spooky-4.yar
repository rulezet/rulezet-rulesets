rule Win_Trojan_Spooky_4
{
strings:
	$a0 = { 74008986d801b4408d960001b90a01cd21b8004233c933d2cd21b43f8d96d201b90300cd21 }


condition:
	$a0
}