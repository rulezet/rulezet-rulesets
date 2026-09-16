rule Win_Trojan_Arcv_9
{
strings:
	$a0 = { 05008a253a2475074647e2f6eb72905eb800428b9c }


condition:
	$a0
}