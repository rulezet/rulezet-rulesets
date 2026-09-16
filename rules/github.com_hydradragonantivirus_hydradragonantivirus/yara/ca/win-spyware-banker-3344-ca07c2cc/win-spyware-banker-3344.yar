rule Win_Spyware_Banker_3344
{
strings:
	$a0 = { adf5e104aa083cc96cc12ac8f11a30cde63510c04aff39575ded6a7bef097b885df105147da30560caedc694d2c8ce2de855940165299de7ed2d2f1d3f2d4a5aaad4133bf6f5 }


condition:
	$a0
}