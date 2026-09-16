rule Win_Trojan_E_22
{
strings:
	$a0 = { 9c502ea003013c0274093c037405589dca020053 }


condition:
	$a0
}