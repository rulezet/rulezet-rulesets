rule Win_Trojan_Neurobasher_1
{
strings:
	$a0 = { 80c0834976629706cb48e661a52247c083e8cf225f50 }


condition:
	$a0
}