rule Win_Trojan_SkyNet_4
{
strings:
	$a0 = { 03b4408d960001b9a102cd21b8004233c933d2cd21b440b91c008d96ed03cd21b801573e }


condition:
	$a0
}