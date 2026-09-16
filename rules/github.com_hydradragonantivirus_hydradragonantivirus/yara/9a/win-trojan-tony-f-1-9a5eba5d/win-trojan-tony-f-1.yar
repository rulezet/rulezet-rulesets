rule Win_Trojan_Tony_F_1
{
strings:
	$a0 = { 5033c933d2b80042cc59b440cc2e8b0e16012e8b }


condition:
	$a0
}