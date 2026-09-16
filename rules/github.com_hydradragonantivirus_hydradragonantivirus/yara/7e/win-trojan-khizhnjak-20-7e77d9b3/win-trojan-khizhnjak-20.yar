rule Win_Trojan_Khizhnjak_20
{
strings:
	$a0 = { bb8803cd13721026807f01fe740926c64701fefec4cd13b98000bb00008a87d4022e888780 }


condition:
	$a0
}