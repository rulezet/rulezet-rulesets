rule Win_Trojan_Peed_13
{
strings:
	$a0 = { 89c381eb41??4000f7db68????ffff8b1c??ffd352682a335f04e8??00000089cde8 }


condition:
	$a0
}