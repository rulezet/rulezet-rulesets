rule Win_Trojan_F_15
{
strings:
	$a0 = { be830041492e8a242e32264f0041492e882446414981fe640475ea5841495ec3 }


condition:
	$a0
}