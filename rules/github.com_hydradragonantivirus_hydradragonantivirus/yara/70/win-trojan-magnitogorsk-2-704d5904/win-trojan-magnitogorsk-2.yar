rule Win_Trojan_Magnitogorsk_2
{
strings:
	$a0 = { be3e0003f7b9c2072e00042ef6ad070046e2f5 }


condition:
	$a0
}