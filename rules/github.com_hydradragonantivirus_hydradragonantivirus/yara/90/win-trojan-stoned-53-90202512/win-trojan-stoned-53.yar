rule Win_Trojan_Stoned_53
{
strings:
	$a0 = { 8dc29d8a85c69da28b7cbf40008a85bd9d8885bd7d4f75f5b80103bb007ccd13 }


condition:
	$a0
}