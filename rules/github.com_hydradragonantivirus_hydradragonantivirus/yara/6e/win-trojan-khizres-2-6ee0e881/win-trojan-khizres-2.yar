rule Win_Trojan_Khizres_2
{
strings:
	$a0 = { 21722eb440b90200bae504cd217222b440b9990490ba1201cd217215b8004233c933d2cd21720a }


condition:
	$a0
}