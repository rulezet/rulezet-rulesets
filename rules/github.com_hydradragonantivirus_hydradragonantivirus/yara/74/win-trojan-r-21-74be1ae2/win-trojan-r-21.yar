rule Win_Trojan_R_21
{
strings:
	$a0 = { 241c3e8b96e4068db61101b9e90231144646e2fa }


condition:
	$a0
}