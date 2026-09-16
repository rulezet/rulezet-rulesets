rule Win_Trojan_Trakia_5
{
strings:
	$a0 = { 02000033d2b98d02b440e89100b8004233c933d2e88700b91800ba8902b440e87c00e94bff }


condition:
	$a0
}