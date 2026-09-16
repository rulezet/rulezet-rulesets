rule Win_Trojan_Grog_17
{
strings:
	$a0 = { 023d2e8b16dc02cd218bd853b43fb90300bad902cd212e }


condition:
	$a0
}