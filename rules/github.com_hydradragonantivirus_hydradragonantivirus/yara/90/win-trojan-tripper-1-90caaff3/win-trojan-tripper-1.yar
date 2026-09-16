rule Win_Trojan_Tripper_1
{
strings:
	$a0 = { b807a38c07b9a007b440cd21724233c933d2b80042cd21 }


condition:
	$a0
}