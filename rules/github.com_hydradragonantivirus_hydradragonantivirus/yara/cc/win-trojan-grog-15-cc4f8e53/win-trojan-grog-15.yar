rule Win_Trojan_Grog_15
{
strings:
	$a0 = { 14908bf48b34b9e90180043c802cade201c346ebf4e8ea }


condition:
	$a0
}