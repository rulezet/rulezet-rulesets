rule Win_Trojan_Exeheader_1
{
strings:
	$a0 = { ba132592cd215b8edb8ec383c3102e011e8a004189 }


condition:
	$a0
}