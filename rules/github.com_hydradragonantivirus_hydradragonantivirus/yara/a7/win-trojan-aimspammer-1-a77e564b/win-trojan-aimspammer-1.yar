rule Win_Trojan_AIMSpammer_1
{
strings:
	$a0 = { 396e6775c33abf5469909142426620362e302068db406c1c456570721865ba42d00379f63146e2c7bea5ee63 }


condition:
	$a0
}