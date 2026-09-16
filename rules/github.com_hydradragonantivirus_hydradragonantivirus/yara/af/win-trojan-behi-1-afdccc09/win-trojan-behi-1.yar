rule Win_Trojan_Behi_1
{
strings:
	$a0 = { bfcf000e57b8200050bf420f1e579a00003e02833eae10007403e99d0c8dbe00fe1657bfd5000e57 }


condition:
	$a0
}