rule Win_Trojan_Puver_3
{
strings:
	$a0 = { 1380353f47480bc075f7d73f3f62bed2ba3ab3f73a3f2fb1ff86263fb2a1843a0cc039686e11b408bef93f3eb4fe86033f77 }


condition:
	$a0
}