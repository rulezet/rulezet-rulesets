rule Win_Trojan_Xute_1
{
strings:
	$a0 = { 76040e0e071fba4fee8bf38bfb32e4fc8a0433c233c186044746e2f483c30e90ffe3 }


condition:
	$a0
}