rule Win_Trojan_DIW_6
{
strings:
	$a0 = { 8b4f025b3d5a4d7503eb459080fd907502ebf6b8024233c933d2cd21b440b92001908bd7cd21 }


condition:
	$a0
}