rule Win_Trojan_Peed_185
{
strings:
	$a0 = { e83800000068b83200006800??40005a59520fc10205????????6a026afee803000000e2edc35589e531db871a0fc102 }


condition:
	$a0
}