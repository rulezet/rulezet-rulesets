rule Win_Trojan_VGEN_261
{
strings:
	$a0 = { ffbaa5042e8916c201b430cd218b2e02ffff008b1e2c008edaa37d008c067b00891ef0ff77fc2e9100c7068100ffff }


condition:
	$a0
}