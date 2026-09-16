rule Win_Trojan_Faerie_1
{
strings:
	$a0 = { 19028d960301b91e01b440cd2133d233c9b80042cd218d961802b90300b440cd218b9639028b }


condition:
	$a0
}