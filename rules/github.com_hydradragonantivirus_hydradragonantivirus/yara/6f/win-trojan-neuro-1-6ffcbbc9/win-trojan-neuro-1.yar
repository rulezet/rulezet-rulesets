rule Win_Trojan_Neuro_1
{
strings:
	$a0 = { aa7a0bd75f2c16772d8de8556dad8f6b3d2620470ca808a66b9a4af40f3116774a7d8e850a7b149e }


condition:
	$a0
}