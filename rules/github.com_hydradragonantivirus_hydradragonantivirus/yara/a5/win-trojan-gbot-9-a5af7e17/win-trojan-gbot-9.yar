rule Win_Trojan_Gbot_9
{
strings:
	$a0 = { 558bec81c4a0fbffff6a006a006aff6a0233d28bcae855000000fc83e8044003d10fafc2906a065a25ff000000663dac00747a6a01506aff6a00506a016a00 }


condition:
	$a0
}