rule Win_Trojan_Green_1
{
strings:
	$a0 = { eb0181e800008bec816e000e008b460083c4028be81e068cc88ed88ec080be2104007406e8de03e8c403c686 }


condition:
	$a0
}