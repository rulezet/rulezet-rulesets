rule Win_Trojan_Crusade_2
{
strings:
	$a0 = { 89044646ebf490549dcf902e33857402ebed90f5fc2e8b04ebf1 }


condition:
	$a0
}