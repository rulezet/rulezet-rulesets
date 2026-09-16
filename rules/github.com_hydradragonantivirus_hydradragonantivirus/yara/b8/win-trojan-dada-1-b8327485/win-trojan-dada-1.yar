rule Win_Trojan_DaDa_1
{
strings:
	$a0 = { 508cc02603060300408ec058c333c08ec026803e00004d }


condition:
	$a0
}