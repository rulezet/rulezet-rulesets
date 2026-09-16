rule Win_Trojan_Vicky_2
{
strings:
	$a0 = { 04b440e83cfec3b8024233d28bcae831fec3b8004233 }


condition:
	$a0
}