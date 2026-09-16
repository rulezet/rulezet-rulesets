rule Win_Trojan_Bancos_703
{
strings:
	$a0 = { 2c4c298cdd9e41e4e128f5db5cc63efad3bce4b28bc1fe177d69201b43693e64f1d2ac7aff0de2b146f3952ea8bf66e2b3f3a528b28da79e437ed28fa81c4d6155 }


condition:
	$a0
}