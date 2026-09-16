rule Win_Trojan_Sirius_41
{
strings:
	$a0 = { 51b9f4fef7d98137320b83c302e2f759da0b3256b3e6240b2c0d8a0ac8b17752ff1d8a3802b4f80cff2ab3f5f8 }


condition:
	$a0
}