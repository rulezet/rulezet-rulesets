rule Win_Trojan_Magnitogorsk_3
{
strings:
	$a0 = { 3e0003f7b9c2092e00042ef6ad070046e2f5 }


condition:
	$a0
}