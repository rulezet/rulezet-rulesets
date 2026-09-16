rule Win_Trojan_Kode_6
{
strings:
	$a0 = { 568b7401bfd90103fe8b058a4d02bf00018905884d02b44ebad00103d6cd217303e99600b443b000ba9e00cd }


condition:
	$a0
}