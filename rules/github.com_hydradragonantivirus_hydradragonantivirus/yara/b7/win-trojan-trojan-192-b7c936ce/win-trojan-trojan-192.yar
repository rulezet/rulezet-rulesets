rule Win_Trojan_Trojan_192
{
strings:
	$a0 = { 21bff404891b8c030e07b82425ba8401 }


condition:
	$a0
}