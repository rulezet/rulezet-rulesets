rule Win_Trojan_E_21
{
strings:
	$a0 = { 2681bdf8014e47751e2681bdfa012d337515b84d5aab268a85fd01aa81c7dd00b91f01b000f3aa }


condition:
	$a0
}