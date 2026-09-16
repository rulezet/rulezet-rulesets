rule Win_Trojan_Chomik_1
{
strings:
	$a0 = { cd213d0001740b545a3bd4750533f6e82500580510 }


condition:
	$a0
}