rule Win_Trojan_Virtob_2
{
strings:
	$a0 = { fce829000000b9d?0d0000538bda6631104086d6408d1413e2f45bc3????0f31ff14245dc355b80080000033c9eb2685c07509cd2ec1e01f79ebeb0ac1eb0974e4c1eb0e75df55e8d2ffffff91e8ccffffff83c410ff742404 }


condition:
	$a0
}