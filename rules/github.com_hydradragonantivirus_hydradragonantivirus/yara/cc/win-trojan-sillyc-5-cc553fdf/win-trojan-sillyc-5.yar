rule Win_Trojan_SillyC_5
{
strings:
	$a0 = { 8896a801e85700b440b9c902ba06012bca8d960601cd217235e84200b801578b8ea6018b96a4 }


condition:
	$a0
}