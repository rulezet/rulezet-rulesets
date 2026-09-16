rule Win_Trojan_RDA_1
{
strings:
	$a0 = { d17d0e80f00207f20bdc2b0147602076d8a7053033aa36007d8e0020399f8bb120c2002036380314 }


condition:
	$a0
}