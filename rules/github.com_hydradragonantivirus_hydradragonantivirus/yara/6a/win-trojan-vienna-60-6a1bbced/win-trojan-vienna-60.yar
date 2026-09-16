rule Win_Trojan_Vienna_60
{
strings:
	$a0 = { 908bf283c60ab90400bf0001f3a48bf206b42fcd219089 }


condition:
	$a0
}