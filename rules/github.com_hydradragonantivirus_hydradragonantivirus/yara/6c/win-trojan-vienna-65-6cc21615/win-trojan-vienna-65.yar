rule Win_Trojan_Vienna_65
{
strings:
	$a0 = { 908bf283c60a90b90400bf0001f3a48bf206b42fcd2190 }


condition:
	$a0
}