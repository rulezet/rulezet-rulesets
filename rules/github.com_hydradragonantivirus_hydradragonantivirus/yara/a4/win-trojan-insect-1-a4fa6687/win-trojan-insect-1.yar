rule Win_Trojan_Insect_1
{
strings:
	$a0 = { c1e00648508ec0b92300be15018bfe56f3a4cb061e561e07b904018a26380180f49050e5428b }


condition:
	$a0
}