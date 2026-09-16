rule Win_Trojan_Mystic_3
{
strings:
	$a0 = { 5d81ed06018d9e1201e855018db66902bf0001a4a5e421c6862301020c00e621c686230100b41a8d968502cd21 }


condition:
	$a0
}