rule Win_Trojan_Kali_2
{
strings:
	$a0 = { 89847102b904008d947002b440cd21b800428b94bd028b8cbb0283e1e080c91d050115cd21 }


condition:
	$a0
}