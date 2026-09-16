rule Win_Trojan_Piter_4
{
strings:
	$a0 = { 2c0033f6ac0a0475fb83c6038bd6 }


condition:
	$a0
}