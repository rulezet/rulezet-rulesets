rule Win_Trojan_R_6
{
strings:
	$a0 = { 0201e800008b2e0001bcfeff81eddb04beee0403f5c604c3c604c6e8ccffe90cfc }


condition:
	$a0
}