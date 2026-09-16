rule Win_Trojan_Vlad_5
{
strings:
	$a0 = { efbe7501cfe94eff9c0ee849ff86c4c3501e51e4603c53 }


condition:
	$a0
}