rule Win_Trojan_Concept_4
{
strings:
	$a0 = { ff01070055e001000400ffff970b00002f01000003000000e014 }


condition:
	$a0
}