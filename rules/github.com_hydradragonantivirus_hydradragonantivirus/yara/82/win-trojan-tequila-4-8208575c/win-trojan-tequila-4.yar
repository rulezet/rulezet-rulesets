rule Win_Trojan_Tequila_4
{
strings:
	$a0 = { e0be6009fc84ebb9600985c18a1439d8301746439081fea00972 }


condition:
	$a0
}