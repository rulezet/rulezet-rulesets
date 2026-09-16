rule Win_Trojan_Small_4238
{
strings:
	$a0 = { 60e800000000596631 }


condition:
	$a0
}