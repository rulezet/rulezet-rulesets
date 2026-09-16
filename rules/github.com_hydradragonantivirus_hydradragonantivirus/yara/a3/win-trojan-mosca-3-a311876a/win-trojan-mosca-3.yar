rule Win_Trojan_Mosca_3
{
strings:
	$a0 = { edbd00008a9e240153b92f0383c10089c95bbe250101ee2e301c46e2fae90100 }


condition:
	$a0
}