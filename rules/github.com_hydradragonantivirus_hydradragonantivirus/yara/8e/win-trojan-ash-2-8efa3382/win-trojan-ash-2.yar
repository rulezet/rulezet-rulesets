rule Win_Trojan_Ash_2
{
strings:
	$a0 = { 0200eb213e8a8649078db63601b911063004d2c046e2f9 }


condition:
	$a0
}