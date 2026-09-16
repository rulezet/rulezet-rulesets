rule Win_Trojan_Lucky_3
{
strings:
	$a0 = { b80057cd21890ebf008916c100b440b9dd0133d2cd21b440b90a00baf501cd21585005e70133d2 }


condition:
	$a0
}