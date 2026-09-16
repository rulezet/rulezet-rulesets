rule Win_Trojan_VGEN_277
{
strings:
	$a0 = { edce01b8addecd2181ff96190f84ab02b80049cd210f82a202b80048bbffffcd2181eb2f000f8292028cc1f913cb }


condition:
	$a0
}