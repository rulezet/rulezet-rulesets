rule Win_Trojan_Donbass_1
{
strings:
	$a0 = { 5192109fec27ddb06e259d0763efe82612bf9d07e466ddb07425e92550eb7118aea0ef24e827077c }


condition:
	$a0
}