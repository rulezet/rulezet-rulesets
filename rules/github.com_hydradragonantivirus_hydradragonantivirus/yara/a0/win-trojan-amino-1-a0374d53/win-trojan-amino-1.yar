rule Win_Trojan_Amino_1
{
strings:
	$a0 = { 76fa9a0236817efac04f7503e9110036817efad75875 }


condition:
	$a0
}