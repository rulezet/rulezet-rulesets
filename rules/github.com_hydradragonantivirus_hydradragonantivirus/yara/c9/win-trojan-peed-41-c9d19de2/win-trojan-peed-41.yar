rule Win_Trojan_Peed_41
{
strings:
	$a0 = { 8b7c241c4001c24f09ff75f8b90196400001c151 }


condition:
	$a0
}