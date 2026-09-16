rule Win_Trojan_VotaDC_1
{
strings:
	$a0 = { b800fecd21fc3c10743c1e8cd8488ed8832e0300358b3e120083ef358ec71f1eb94f028d76fdbf0001f3a433c08ed8 }


condition:
	$a0
}