rule Win_Trojan_Zoom_1
{
strings:
	$a0 = { 4d5a74502e8826ed022e8826d303b80242998bcacdfc3dfbfe7739050001a35803b440b9040151 }


condition:
	$a0
}