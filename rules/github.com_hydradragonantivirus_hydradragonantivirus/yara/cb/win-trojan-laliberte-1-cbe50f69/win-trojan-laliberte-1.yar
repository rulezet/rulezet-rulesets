rule Win_Trojan_LaLiberte_1
{
strings:
	$a0 = { f57321b80040b9e000ba0002cd217214b8004233d233 }


condition:
	$a0
}