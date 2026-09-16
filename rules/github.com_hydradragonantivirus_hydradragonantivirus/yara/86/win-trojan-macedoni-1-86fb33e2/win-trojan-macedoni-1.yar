rule Win_Trojan_Macedoni_1
{
strings:
	$a0 = { cd2180fcba7527e871002e8b042ea300012e8b4402 }


condition:
	$a0
}