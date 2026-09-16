rule Win_Trojan_Feebs_29
{
strings:
	$a0 = { 3d7662733e[0-4]3d22[0-8]3d222522 }

	$a1 = { 3d7265706c61636528[0-20]3d756e65736361706528[0-4]293c2f7363726970743e }


condition:
	$a0 and $a1
}