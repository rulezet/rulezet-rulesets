rule Win_Trojan_Philis_150
{
strings:
	$a0 = { 559090908bec90909090ebce }


condition:
	$a0
}