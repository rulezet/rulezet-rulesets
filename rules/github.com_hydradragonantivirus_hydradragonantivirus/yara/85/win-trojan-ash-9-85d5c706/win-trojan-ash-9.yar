rule Win_Trojan_Ash_9
{
strings:
	$a0 = { 9090cd209001e800005d81ed0b01bf00018db60401b90400fcf3a4b41a8d }


condition:
	$a0
}