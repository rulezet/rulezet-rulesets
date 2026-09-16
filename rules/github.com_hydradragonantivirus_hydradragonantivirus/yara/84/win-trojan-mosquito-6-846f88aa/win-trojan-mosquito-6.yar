rule Win_Trojan_Mosquito_6
{
strings:
	$a0 = { 5b83eb030e53eb1f90ea8b042507ea90052dcfe9de00e9f9010000e107d99e4a1e2f054b0a2000b800e2cd2180 }


condition:
	$a0
}