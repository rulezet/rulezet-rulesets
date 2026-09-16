rule Win_Trojan_Hydra_4
{
strings:
	$a0 = { be00018ec0f3a4b41aba3501cd21 }


condition:
	$a0
}