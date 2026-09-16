rule Win_Trojan_FrodoSoft_3
{
strings:
	$a0 = { 0600be9614b93503311c46e0fb87e8450550bf0506b906078bb25304f5a2588f827f04085e8f827d04b24cbd0616cb }


condition:
	$a0
}