rule Win_Trojan_AOL_23
{
strings:
	$a0 = { 499a38100064020a00433a5c646f735c2a2e2a0000fb5342499a380c007c020600433a5c2a2e2a }


condition:
	$a0
}