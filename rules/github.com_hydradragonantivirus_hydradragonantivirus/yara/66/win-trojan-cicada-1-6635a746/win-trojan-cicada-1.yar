rule Win_Trojan_Cicada_1
{
strings:
	$a0 = { 9c5053515257561e062ea136028ed8813e0000eb3c7502eb111e07b8c09e8ed831 }


condition:
	$a0
}