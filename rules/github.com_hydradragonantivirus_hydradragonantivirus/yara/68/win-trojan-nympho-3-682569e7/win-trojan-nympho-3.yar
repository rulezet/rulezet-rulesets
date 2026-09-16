rule Win_Trojan_Nympho_3
{
strings:
	$a0 = { 81ea000189160101ba0001b94703b440cd2126c74515000026c74517000087d659b440cd21 }


condition:
	$a0
}