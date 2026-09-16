rule Win_Trojan_Trojan_73
{
strings:
	$a0 = { f90c5c96d79836c706bd01cd203ec706bd012ec71405ec3e298f }


condition:
	$a0
}