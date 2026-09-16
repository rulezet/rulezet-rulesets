rule Win_Trojan_Chemnitz_1
{
strings:
	$a0 = { 4b74092eff2eb400b4161e055053515256571e06550e }


condition:
	$a0
}