rule Win_Trojan_Andromeda_1
{
strings:
	$a0 = { dfafb430cd2181ffc3c3751c8ccb2ea11a032bd82e891e1a032ea10c032ea31803071f2eff2e180307068cc048 }


condition:
	$a0
}