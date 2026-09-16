rule Win_Trojan_Lacimehc_1
{
strings:
	$a0 = { 660b4febd5a3add82b5feba67d292b52da24660ba6553d29bca65ddf2b52892aba4380155febb2b1 }


condition:
	$a0
}