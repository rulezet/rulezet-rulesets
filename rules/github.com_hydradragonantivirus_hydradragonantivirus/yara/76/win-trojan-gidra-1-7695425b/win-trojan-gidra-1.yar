rule Win_Trojan_Gidra_1
{
strings:
	$a0 = { 408d944f01b9d50190cd217303e954ffb8004233c933d2 }


condition:
	$a0
}