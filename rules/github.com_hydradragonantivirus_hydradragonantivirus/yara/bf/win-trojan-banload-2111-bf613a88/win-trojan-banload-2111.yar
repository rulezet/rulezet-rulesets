rule Win_Trojan_Banload_2111
{
strings:
	$a0 = { 60be00204c008dbe00f0f3ffc787a4200f006bea40995783cdffeb0e909090908a064688074701db75078b1e83 }


condition:
	$a0
}