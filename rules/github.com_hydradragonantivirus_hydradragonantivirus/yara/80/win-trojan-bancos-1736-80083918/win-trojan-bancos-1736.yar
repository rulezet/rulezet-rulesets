rule Win_Trojan_Bancos_1736
{
strings:
	$a0 = { 385310b363034cd62b8780ad93fd1ba8ba448cad3a2abc86d127e3c048693a4883b1eb038ed01b8d4fd5b9b936cae32a343c36a1d4d1211cb0e4ad8b538fcd0e84e79a854295 }


condition:
	$a0
}