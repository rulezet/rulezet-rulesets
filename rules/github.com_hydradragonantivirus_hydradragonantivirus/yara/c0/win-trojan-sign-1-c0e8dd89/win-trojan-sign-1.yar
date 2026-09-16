rule Win_Trojan_Sign_1
{
strings:
	$a0 = { 4301ba000103d5b440b96702cd217234b000e83600ba470303d5b90a00b440cd217221b43ecd21 }


condition:
	$a0
}