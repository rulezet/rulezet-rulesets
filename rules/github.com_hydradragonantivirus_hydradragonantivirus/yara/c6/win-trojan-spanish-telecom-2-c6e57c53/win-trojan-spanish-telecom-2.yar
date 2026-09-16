rule Win_Trojan_Spanish_Telecom_2
{
strings:
	$a0 = { eb150e1fbb3c7c8b0735ffff8907434381fb5a7d72 }


condition:
	$a0
}