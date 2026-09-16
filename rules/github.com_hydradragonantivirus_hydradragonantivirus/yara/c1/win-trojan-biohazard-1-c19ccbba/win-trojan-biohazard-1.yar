rule Win_Trojan_Biohazard_1
{
strings:
	$a0 = { 110399cd217302722db80042b9000099cd21b440b90500baac01cd217218b801572e8b0ea5 }


condition:
	$a0
}