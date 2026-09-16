rule Win_Trojan_VLAD_7
{
strings:
	$a0 = { c089c1482ae88bd1d1c18ad0f7f1f7f1f7f1f7f1f7f14901c2f7f1f7f1f7f192be0001b8bd51cd213d51bd74538cd8 }


condition:
	$a0
}