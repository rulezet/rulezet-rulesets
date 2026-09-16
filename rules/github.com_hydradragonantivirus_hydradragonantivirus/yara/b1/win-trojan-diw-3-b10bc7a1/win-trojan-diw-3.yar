rule Win_Trojan_DIW_3
{
strings:
	$a0 = { 7502eb4380fd907502ebf7b8024233c933d2cd21b440b91f018bd7cd21b8004233c933d2cd }


condition:
	$a0
}