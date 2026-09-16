rule Win_Trojan_Zicar_2
{
strings:
	$a0 = { 58354f2150254041b07ee670e6714141b87f0333d2b280cd13ebf3 }


condition:
	$a0
}