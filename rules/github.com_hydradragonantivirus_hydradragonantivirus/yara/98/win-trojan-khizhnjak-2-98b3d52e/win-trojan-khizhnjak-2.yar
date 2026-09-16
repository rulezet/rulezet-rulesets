rule Win_Trojan_Khizhnjak_2
{
strings:
	$a0 = { c401ba1001cd217215b8004233c933d2cd21720ab440b90300bacf02cd21b43ecd21b98000 }


condition:
	$a0
}