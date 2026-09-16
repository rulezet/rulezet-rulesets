rule Win_Trojan_Peed_430
{
strings:
	$a0 = { 4883e891b906000000057525ea362bd753575683c63a0bc1ff15f8204000ff153c214000 }


condition:
	$a0
}