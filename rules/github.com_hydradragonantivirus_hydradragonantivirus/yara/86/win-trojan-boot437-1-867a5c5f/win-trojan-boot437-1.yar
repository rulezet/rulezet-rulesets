rule Win_Trojan_Boot437_1
{
strings:
	$a0 = { 03be0001b90600fca67504e2fbeb7080fa807213b600b90600b8010351529cff1ec5007331eb }


condition:
	$a0
}