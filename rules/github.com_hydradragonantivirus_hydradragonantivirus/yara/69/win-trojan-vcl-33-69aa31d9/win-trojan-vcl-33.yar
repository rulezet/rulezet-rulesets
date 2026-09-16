rule Win_Trojan_VCL_33
{
strings:
	$a0 = { ee0e01eb0200008b841f01eb020000b9aa018dbc3301eb020000310583c702e2f9 }


condition:
	$a0
}