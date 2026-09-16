rule Win_Trojan_Trojan_342
{
strings:
	$a0 = { 166625ebee5bb985230e81eb9f231f8a47fffec8 }


condition:
	$a0
}