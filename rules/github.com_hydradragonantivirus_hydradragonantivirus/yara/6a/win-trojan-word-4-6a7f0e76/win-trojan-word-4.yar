rule Win_Trojan_Word_4
{
strings:
	$a0 = { bf250780353b4781ff840c72 }


condition:
	$a0
}