rule Win_Trojan_Virus_2
{
strings:
	$a0 = { 4e894402b440b9bd00ba0701cd21b8004233c933d2cd21b440b90300468bd6cd21b8015733 }


condition:
	$a0
}