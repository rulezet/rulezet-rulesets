rule Win_Trojan_Win_34
{
strings:
	$a0 = { 57696e33322e484c4c502e5a617573686b612e576f726d005a617573686b6100 }


condition:
	$a0
}