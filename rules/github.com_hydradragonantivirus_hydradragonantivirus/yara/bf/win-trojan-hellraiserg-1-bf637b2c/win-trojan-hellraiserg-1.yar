rule Win_Trojan_HellRaiserG_1
{
strings:
	$a0 = { be3a018bfeb96607fcad33060301ab4975f7 }


condition:
	$a0
}