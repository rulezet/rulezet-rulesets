rule Win_Trojan_CivilWar_23
{
strings:
	$a0 = { 02008d96ea01cd21b80242e82100b440b915028d960601cd218b96e0018b8ee2018b9ede01 }


condition:
	$a0
}