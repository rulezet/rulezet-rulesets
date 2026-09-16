rule Win_Trojan_Mosca_2
{
strings:
	$a0 = { edbd00008a9e240153b93a0583c10089c95bbe250101ee2e301c46e2fae90100 }


condition:
	$a0
}