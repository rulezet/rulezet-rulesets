rule Win_Trojan_Party_1
{
strings:
	$a0 = { cd110bc07503e9d601cc44448bec8b76fe81ee07015681c6e002bf0001a5a5b44781eee40281c6a70232d2cd215e }


condition:
	$a0
}