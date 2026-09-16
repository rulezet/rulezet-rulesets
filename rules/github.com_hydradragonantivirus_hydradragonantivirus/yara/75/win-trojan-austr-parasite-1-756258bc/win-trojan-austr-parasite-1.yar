rule Win_Trojan_Austr_Parasite_1
{
strings:
	$a0 = { bdd200b8????8d9e1201b9d601310743e2fb }


condition:
	$a0
}