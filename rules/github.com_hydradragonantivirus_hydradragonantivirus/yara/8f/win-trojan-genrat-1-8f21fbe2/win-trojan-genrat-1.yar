rule Win_Trojan_Genrat_1
{
strings:
	$a0 = { 0300e9b2feb91103ba0801e82a00c31f075d5f5e612eff }


condition:
	$a0
}