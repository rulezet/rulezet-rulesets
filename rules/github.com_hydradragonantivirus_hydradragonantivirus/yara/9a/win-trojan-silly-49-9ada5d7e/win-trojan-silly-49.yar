rule Win_Trojan_Silly_49
{
strings:
	$a0 = { 2150b440b9a900cd21b8004233c9cd21c6060000e88f060100b440b90300cd21b43ecd211f }


condition:
	$a0
}