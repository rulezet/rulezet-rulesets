rule Win_Trojan_Dune_1
{
strings:
	$a0 = { 21b8004233c933d2cd21b440b90500bad901cd21b8024233c933d2cd21b44033d2b9e301cd215a }


condition:
	$a0
}