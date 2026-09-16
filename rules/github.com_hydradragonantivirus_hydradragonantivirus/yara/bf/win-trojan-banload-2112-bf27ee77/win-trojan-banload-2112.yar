rule Win_Trojan_Banload_2112
{
strings:
	$a0 = { 60be00204c008dbe00f0f3ffc787a4300f002ad48d345783cdffeb0e909090908a064688074701db75078b1e83 }


condition:
	$a0
}