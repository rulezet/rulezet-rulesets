rule Win_Trojan_Blackhole_38
{
strings:
	$a0 = { 3d70726f746f747970652d323b7d6361746368286261776729 }


condition:
	$a0
}