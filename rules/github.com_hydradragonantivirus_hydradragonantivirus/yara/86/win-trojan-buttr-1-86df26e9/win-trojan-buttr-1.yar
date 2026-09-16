rule Win_Trojan_Buttr_1
{
strings:
	$a0 = { 01cd209090e800005d81ed0b01bf00018db60401b90400fcf3a4b41a8d }


condition:
	$a0
}