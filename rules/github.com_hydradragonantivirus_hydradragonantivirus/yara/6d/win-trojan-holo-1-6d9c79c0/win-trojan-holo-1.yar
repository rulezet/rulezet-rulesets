rule Win_Trojan_Holo_1
{
strings:
	$a0 = { e800008bdcb60033c9b2d2fa5151b6e15959875ffeb26c53585db26083ed0abe }


condition:
	$a0
}