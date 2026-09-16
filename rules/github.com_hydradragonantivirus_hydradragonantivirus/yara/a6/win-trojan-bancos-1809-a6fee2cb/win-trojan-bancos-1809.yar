rule Win_Trojan_Bancos_1809
{
strings:
	$a0 = { ebbca3e049bce03c2d4b37ae924ce280f529b0206d8380aad0ca41df472849ecefff87ad280e982e879a13a818231bab9c83d53b484bdad1160b755afd663888d276d9db1ffa }


condition:
	$a0
}