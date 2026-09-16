rule Win_Trojan_F_12
{
strings:
	$a0 = { be82002e8a242e322651008bc02e8824468bc081fe710475ea585e8bc0c3 }


condition:
	$a0
}