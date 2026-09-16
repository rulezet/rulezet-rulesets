rule Win_Trojan_Bancos_1898
{
strings:
	$a0 = { dac07a5de01320be867ffdc26a44b09fd5bcfb0a71c2ccc99c53ec1c124ad7bb32f8516ce8ab9c0c1f38bd3f0ad2edf5c9545bb7f94d224efdc0143b4f4ed773d13fb75a30ee }


condition:
	$a0
}