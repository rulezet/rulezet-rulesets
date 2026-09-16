rule Win_Trojan_Deliver_1
{
strings:
	$a0 = { 5de80200dea40356fe87f258bd010087ebeb01dd0e1fbf6a00474732e4b040500740bd5f0d3e8b0245459392 }


condition:
	$a0
}