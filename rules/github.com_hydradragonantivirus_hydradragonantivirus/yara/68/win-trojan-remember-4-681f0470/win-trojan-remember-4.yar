rule Win_Trojan_Remember_4
{
strings:
	$a0 = { fabc00008be5fbcd01cccd75e800005d81ed1601b42acd2181fa18047521b80091cd103d00917417b84e80cd10b4 }


condition:
	$a0
}