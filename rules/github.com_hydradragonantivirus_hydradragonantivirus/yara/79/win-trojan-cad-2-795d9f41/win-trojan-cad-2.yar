rule Win_Trojan_CAD_2
{
strings:
	$a0 = { cd213c07753581c35d042e813f4d5a7413bf000189de }


condition:
	$a0
}