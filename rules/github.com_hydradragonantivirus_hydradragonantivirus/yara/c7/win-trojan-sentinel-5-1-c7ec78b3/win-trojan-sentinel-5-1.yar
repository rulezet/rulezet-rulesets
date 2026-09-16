rule Win_Trojan_Sentinel_5_1
{
strings:
	$a0 = { 0312cd2f1e0731c989cf49d1e9b82e3a }


condition:
	$a0
}