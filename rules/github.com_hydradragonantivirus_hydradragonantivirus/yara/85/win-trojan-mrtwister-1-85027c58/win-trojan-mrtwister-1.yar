rule Win_Trojan_MrTwister_1
{
strings:
	$a0 = { b000b708b500b100b618b24fb707cd10b700b307b615b2051e07bddf01b91c00b413cd10b700b307b616b2051e07bdfc01b92300b413cd10b400cd1698b9 }


condition:
	$a0
}