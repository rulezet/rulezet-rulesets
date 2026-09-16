rule Win_Trojan_Bryansk_1
{
strings:
	$a0 = { cd21b90700bf03018b3581c69a03bf0001fcf3a4eb2290 }


condition:
	$a0
}