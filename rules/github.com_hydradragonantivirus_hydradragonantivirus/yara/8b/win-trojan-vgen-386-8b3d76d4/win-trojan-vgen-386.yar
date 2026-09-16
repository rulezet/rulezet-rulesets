rule Win_Trojan_VGEN_386
{
strings:
	$a0 = { 01bd10012e81760000004545e2f6e800005d81ed13011e060e1f0e078db6cb018dbec301a5a5a5a5c686710302b4 }


condition:
	$a0
}