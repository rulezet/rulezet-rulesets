rule Win_Trojan_Austr_32
{
strings:
	$a0 = { 40b92401ba0000cd21b8004233c933d2cd21b90300ba0000b440cd215a59b80157cd21b43ecd21 }


condition:
	$a0
}