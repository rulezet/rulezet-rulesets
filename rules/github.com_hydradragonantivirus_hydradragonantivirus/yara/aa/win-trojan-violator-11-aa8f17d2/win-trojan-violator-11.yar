rule Win_Trojan_Violator_11
{
strings:
	$a0 = { 5504e81000803e5504197420fe0655 }


condition:
	$a0
}