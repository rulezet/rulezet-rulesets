rule Win_Trojan_DrEt_1
{
strings:
	$a0 = { 9001b2460da8b9647b445ffe44b7016a51aa76b9cbe06ed0ef94d06f6ba576da }


condition:
	$a0
}