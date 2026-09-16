rule Win_Trojan_Australian_8
{
strings:
	$a0 = { c001b8b440b9e700ba0001cd21b8004233c933d2cd21b440b90400ba0001cd215a595840cd21 }


condition:
	$a0
}