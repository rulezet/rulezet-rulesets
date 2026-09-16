rule Win_Trojan_Khizres_1
{
strings:
	$a0 = { 7221b440b97c04ba1201cd217215b8004233c933d2cd21720ab440b90300bac804cd21b43ecd }


condition:
	$a0
}