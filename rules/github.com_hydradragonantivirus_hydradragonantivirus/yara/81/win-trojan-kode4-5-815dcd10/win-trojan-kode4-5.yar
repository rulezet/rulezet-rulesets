rule Win_Trojan_Kode4_5
{
strings:
	$a0 = { b440b90300ba1a0203d6cd2133c933d2b80242cd21ba030103d6b91d0190b440cd21 }


condition:
	$a0
}