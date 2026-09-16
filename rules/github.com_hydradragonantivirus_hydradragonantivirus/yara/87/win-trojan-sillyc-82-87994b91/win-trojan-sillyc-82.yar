rule Win_Trojan_SillyC_82
{
strings:
	$a0 = { 40b9bd00ba0701cd21b8004233c933d2cd21b440b90300 }


condition:
	$a0
}