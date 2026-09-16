rule Win_Trojan_HWF_2
{
strings:
	$a0 = { bb32280e70001fb9bcf25185e181c1b010589090280785c348fa43fce2f6 }


condition:
	$a0
}