rule Win_Trojan_Zzz_1
{
strings:
	$a0 = { 01b4408b1e3901ba00018b0ea101cd217303e98d00ff0e0501a19f01a3ab018b0eab018b }


condition:
	$a0
}