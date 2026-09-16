rule Win_Trojan_NRLG_1
{
strings:
	$a0 = { f615eb0190800579eb0190802d624747e2925cc000 }


condition:
	$a0
}