rule Win_Trojan_Slovakia_2
{
strings:
	$a0 = { 112e8a5e0032da2e885e0080c21145e2f0c3bd030055bb }


condition:
	$a0
}