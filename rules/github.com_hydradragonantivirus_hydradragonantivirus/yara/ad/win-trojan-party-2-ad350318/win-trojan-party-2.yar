rule Win_Trojan_Party_2
{
strings:
	$a0 = { 90f0e8000033c0cd110bc07503e9d601cc444489e58b76fe81ee07015681c6e002bf0001a5a5b44781eee40281c6 }


condition:
	$a0
}