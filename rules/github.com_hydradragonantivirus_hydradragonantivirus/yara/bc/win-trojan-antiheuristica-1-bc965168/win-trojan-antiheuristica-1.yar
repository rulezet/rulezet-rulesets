rule Win_Trojan_AntiHeuristica_1
{
strings:
	$a0 = { 1ffa97553ac83dc69905e2661759496a5e59072b4e6a40059b780425c4162aec3e07cf0f36052d8db618018b869403b93c0131044646e2fac3 }


condition:
	$a0
}