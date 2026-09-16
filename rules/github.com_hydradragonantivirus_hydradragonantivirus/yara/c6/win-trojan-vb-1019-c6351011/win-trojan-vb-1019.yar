rule Win_Trojan_VB_1019
{
strings:
	$a0 = { 5c00720075006e }

	$a1 = { 32005c00630073006d006d002e006500780065 }

	$a2 = { 5c00730078006d006d002e0064006c006c }


condition:
	$a0 and $a1 and $a2
}