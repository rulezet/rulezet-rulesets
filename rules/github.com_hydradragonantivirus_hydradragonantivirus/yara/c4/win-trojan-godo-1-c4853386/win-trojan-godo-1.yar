rule Win_Trojan_Godo_1
{
strings:
	$a0 = { 2f7365637572652f757064617465636865636b2e68746d6c3f69643d }


condition:
	$a0
}