rule Win_Trojan_Apparition_3
{
strings:
	$a0 = { d6b9b702b4408b9c6206cd21b800428b9c6206b90000ba0000cd21b4408b9c6206b92000 }


condition:
	$a0
}