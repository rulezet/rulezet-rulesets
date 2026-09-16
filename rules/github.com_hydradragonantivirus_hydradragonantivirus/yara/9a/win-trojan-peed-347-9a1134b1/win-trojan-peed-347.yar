rule Win_Trojan_Peed_347
{
strings:
	$a0 = { 2d4433000040e840000000ab5052516a0058 }


condition:
	$a0
}