rule Win_Trojan_L_24
{
strings:
	$a0 = { 0301882f4381fb1f057ef159c3ba00018b1ee50153e8e0ff5bb9e703b440cd2153 }


condition:
	$a0
}