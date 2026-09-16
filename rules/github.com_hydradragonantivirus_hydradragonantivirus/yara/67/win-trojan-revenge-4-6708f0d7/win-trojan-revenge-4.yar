rule Win_Trojan_Revenge_4
{
strings:
	$a0 = { c60508008bf081fe30757ce2e8f00eb8060050b8050050e8ef095959b8b70150e8af0759b809 }


condition:
	$a0
}