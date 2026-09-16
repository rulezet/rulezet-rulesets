rule Win_Trojan_VGEN_760
{
strings:
	$a0 = { 2836b9d902be60063114310c46e2f94c94ce75c9c94278cbce2f7775684fe618f5e68a9aaddbb6dddd60038da02966 }


condition:
	$a0
}