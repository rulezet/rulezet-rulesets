rule Win_Trojan_Kode_1
{
strings:
	$a0 = { 03568b740156bf00018db49101a4a55eb44e8d948801cd217302eb65b8023dba9e00cd217302eb5993b43fb903 }


condition:
	$a0
}