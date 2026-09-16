rule Win_Trojan_Macaroni_3
{
strings:
	$a0 = { 40b9fc00ba0701cd21b8004233c933d2cd21b440b90300468bd6cd21b8015733c933d2cd21b43e }


condition:
	$a0
}