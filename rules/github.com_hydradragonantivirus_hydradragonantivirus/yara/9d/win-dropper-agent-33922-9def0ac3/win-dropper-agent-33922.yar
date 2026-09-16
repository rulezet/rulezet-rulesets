rule Win_Dropper_Agent_33922
{
strings:
	$a0 = { 53568b352c804000576a00ffd668d8314300e8a7a0ffff5933db }


condition:
	$a0
}