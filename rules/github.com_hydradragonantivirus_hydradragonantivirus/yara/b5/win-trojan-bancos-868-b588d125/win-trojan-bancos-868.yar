rule Win_Trojan_Bancos_868
{
strings:
	$a0 = { 3e9b862a5372d4e23d55d029c7e23628cae0c4cbcb5c399ca03aeb3821984be2546280ef46986f112ced415d50b6e96d084feaa60c894020608fbc51097e90a51e }


condition:
	$a0
}