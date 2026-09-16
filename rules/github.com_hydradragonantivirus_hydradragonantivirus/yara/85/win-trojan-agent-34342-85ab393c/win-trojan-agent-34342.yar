rule Win_Trojan_Agent_34342
{
strings:
	$a0 = { 81c0d4d4019687d2525a87d281e8d4d4019683ec04534668665be86ae8 }


condition:
	$a0
}