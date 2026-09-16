rule Win_Trojan_Ganja_1
{
strings:
	$a0 = { 40b9b5018bd5cd21c38cc00510002e0386210150b8050333dbcd162effb61f011e0e1f8d96b501 }


condition:
	$a0
}