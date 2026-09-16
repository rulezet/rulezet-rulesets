rule Win_Trojan_Datacrime_3
{
strings:
	$a0 = { b402cd2143fec975f1bbad01b500ba80 }


condition:
	$a0
}