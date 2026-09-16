rule Win_Trojan_Remember_5
{
strings:
	$a0 = { bc00008be5fbcd01cccd75e800005d81ed1601b42acd2181fa18047522b80091cd103d00917418b84e80cd10b4 }


condition:
	$a0
}