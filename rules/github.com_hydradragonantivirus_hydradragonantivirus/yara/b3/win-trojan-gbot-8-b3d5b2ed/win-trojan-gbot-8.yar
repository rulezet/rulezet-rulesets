rule Win_Trojan_Gbot_8
{
strings:
	$a0 = { 558bec81c4a0fbffff6a006a006aff6a006a0233d28bcae84c000000fc83e8044003d10fafc2906a06f95a25ff000000663dac0074726a00f2 }


condition:
	$a0
}