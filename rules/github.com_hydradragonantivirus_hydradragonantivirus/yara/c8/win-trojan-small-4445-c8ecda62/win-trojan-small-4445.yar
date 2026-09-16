rule Win_Trojan_Small_4445
{
strings:
	$a0 = { 68????40008b042468e00a000050e85e0000005068????4000e8 }


condition:
	$a0
}