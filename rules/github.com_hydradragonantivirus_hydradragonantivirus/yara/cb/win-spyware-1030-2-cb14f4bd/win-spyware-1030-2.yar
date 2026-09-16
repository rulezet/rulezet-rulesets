rule Win_Spyware_1030_2
{
strings:
	$a0 = { 6b792d6c6162733c00da732d11bfb57406142e73796d61df63b1118d8815b09a615696b0bf8c6d6361 }


condition:
	$a0
}