rule Win_Trojan_Small_4051
{
strings:
	$a0 = { e80e00000089f82d315d22fd05555522fdeb3feb0083c404eb28ba??????006a006a00ff141a8d88453412ff294d }


condition:
	$a0
}