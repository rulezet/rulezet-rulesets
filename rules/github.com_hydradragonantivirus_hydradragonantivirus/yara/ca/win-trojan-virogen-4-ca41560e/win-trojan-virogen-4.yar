rule Win_Trojan_Virogen_4
{
strings:
	$a0 = { fbfcfaf9fbf5beaf00faf9fbfcfaf590fbfcfaf9fbfcfaf9fbfcfaf9fbfcfaf9fbfcfaf9fbfcfab87307faf9fbfcfa }


condition:
	$a0
}