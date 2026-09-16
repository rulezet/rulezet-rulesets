rule Win_Trojan_Riot_26
{
strings:
	$a0 = { 01faba4559cd16e800005d81ed1301e87401e90200cd20 }


condition:
	$a0
}