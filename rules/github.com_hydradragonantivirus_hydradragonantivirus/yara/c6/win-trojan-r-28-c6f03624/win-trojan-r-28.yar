rule Win_Trojan_R_28
{
strings:
	$a0 = { 9b013ec78699014952b8004233c933d2cd21b440b91c008d968701cd217231eb014f8db6b901 }


condition:
	$a0
}