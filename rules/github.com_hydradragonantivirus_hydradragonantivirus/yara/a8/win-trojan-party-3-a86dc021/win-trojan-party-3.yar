rule Win_Trojan_Party_3
{
strings:
	$a0 = { cd110bc07503e9d701cc44448bec8b76fe81ee07015681c6e102bf0001a5a5b44781eee50281c6a80232d2cd215e }


condition:
	$a0
}