rule Win_Trojan_L_34
{
strings:
	$a0 = { 018b161601b934012e311483c602e80300e2f5c3c38619ff2162b43cb230cd13b47532e08d84 }


condition:
	$a0
}