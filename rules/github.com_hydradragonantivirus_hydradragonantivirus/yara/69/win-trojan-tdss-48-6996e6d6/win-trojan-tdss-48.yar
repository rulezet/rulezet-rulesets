rule Win_Trojan_TDSS_48
{
strings:
	$a0 = { 8b483c83ec0489c601c18d5118b9df0000000fb602494288034383f9ff75f38b }


condition:
	$a0
}