rule Win_Trojan_CmosKiller_3
{
strings:
	$a0 = { b85000e83000b051e82b008af7b07de819008af3b07ee81200fbb0fee664ebf9247fe670eb00 }


condition:
	$a0
}