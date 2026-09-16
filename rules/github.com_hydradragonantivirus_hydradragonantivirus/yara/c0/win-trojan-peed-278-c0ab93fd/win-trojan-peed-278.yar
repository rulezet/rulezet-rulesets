rule Win_Trojan_Peed_278
{
strings:
	$a0 = { e85e0000005589e5518b7d14b9b80b000081c1581b000066abc1c80ac1c806aa }


condition:
	$a0
}