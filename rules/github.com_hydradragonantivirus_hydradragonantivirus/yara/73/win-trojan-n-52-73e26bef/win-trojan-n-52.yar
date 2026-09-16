rule Win_Trojan_N_52
{
strings:
	$a0 = { c0fa8ed0bc007cfb8ec48bd8cd13b90b00b80702cd137302cd1806b83f0050 }


condition:
	$a0
}