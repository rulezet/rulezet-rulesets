rule Win_Trojan_Deicide_8
{
strings:
	$a0 = { 5000ba0000cd26b409ba0301cd21ebfe8ad0b40e }


condition:
	$a0
}