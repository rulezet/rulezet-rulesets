rule Win_Trojan_Oggo_2
{
strings:
	$a0 = { 7fdb5d7fdba552979754205421a1055ddb1408511e61a9841a7fdb5dd24a4f51c62b142f2e2d2c2b }


condition:
	$a0
}