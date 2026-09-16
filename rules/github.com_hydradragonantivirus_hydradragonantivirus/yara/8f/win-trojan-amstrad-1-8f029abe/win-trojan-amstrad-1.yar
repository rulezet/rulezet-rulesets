rule Win_Trojan_Amstrad_1
{
strings:
	$a0 = { 217260ba7d02b8023dcd21a31401 }


condition:
	$a0
}