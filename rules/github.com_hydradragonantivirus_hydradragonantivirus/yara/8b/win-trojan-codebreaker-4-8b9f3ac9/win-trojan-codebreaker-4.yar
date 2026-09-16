rule Win_Trojan_CodeBreaker_4
{
strings:
	$a0 = { 8916c601b44099b9c001cd21b8004233c999cd21b4 }


condition:
	$a0
}