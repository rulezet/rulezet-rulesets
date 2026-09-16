rule Win_Trojan_Parasite_6
{
strings:
	$a0 = { b96001ba0001cd21b8004233c933d2cd21b440b103ba6101803e3c01f87405b118ba6402cd21 }


condition:
	$a0
}