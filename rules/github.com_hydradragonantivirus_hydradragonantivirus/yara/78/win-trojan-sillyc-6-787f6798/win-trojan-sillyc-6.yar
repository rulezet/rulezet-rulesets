rule Win_Trojan_SillyC_6
{
strings:
	$a0 = { 96b901e85700b440b9ed02ba06012bca8d960601cd217235e84200b801578b8eb7018b96b5 }


condition:
	$a0
}