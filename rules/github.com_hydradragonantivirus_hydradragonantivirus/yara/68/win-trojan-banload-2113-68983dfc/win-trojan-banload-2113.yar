rule Win_Trojan_Banload_2113
{
strings:
	$a0 = { 60be00f0da008dbe002065ff5783cdffeb109090909090908a064688074701db75078b1e83eefc11db72edb801 }


condition:
	$a0
}