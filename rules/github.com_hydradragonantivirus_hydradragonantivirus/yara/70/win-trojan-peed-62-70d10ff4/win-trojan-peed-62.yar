rule Win_Trojan_Peed_62
{
strings:
	$a0 = { e90f00000039d80f8e01000000c358e974000000bad7 }


condition:
	$a0
}