rule Win_Trojan_Cookiem_2
{
strings:
	$a0 = { 6f7074696f6e732e766972757370726f74656374696f6e203d202833202a203029 }


condition:
	$a0
}