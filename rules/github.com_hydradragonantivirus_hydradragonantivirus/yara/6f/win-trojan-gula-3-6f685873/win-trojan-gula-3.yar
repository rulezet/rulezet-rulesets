rule Win_Trojan_Gula_3
{
strings:
	$a0 = { 02ebe793b8004233c933d2cd21b440b92c01ba0001cd21b43ecd21ebcdb44ccd214572726f7220 }


condition:
	$a0
}