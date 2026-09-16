rule Win_Trojan_Dialer_833
{
strings:
	$a0 = { 6f1c70656e29015f1c350e302c0d39060b01c144??4574cb[0-8]1c044e5b }


condition:
	$a0
}