rule Win_Trojan_Cannabis_1
{
strings:
	$a0 = { 587da14c003bc3742da3ab7da14e00 }


condition:
	$a0
}