rule Win_Trojan_Anke_1
{
strings:
	$a0 = { a30501c6064902b8b440b91f02ba0001cd21b8004233c933d2cd21b440b90400ba0001cd21 }


condition:
	$a0
}