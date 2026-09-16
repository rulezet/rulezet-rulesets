rule Win_Trojan_WhaleMutant_7
{
strings:
	$a0 = { 83c30249c35ae8f4ff742eebf9520e1fe8230081ea }


condition:
	$a0
}