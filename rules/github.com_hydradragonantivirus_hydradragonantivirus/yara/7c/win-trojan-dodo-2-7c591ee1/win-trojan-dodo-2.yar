rule Win_Trojan_Dodo_2
{
strings:
	$a0 = { 33d233c9cd21b440b99801ba0001cd21 }


condition:
	$a0
}