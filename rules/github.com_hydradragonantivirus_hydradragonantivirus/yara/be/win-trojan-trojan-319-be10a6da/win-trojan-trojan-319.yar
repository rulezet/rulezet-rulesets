rule Win_Trojan_Trojan_319
{
strings:
	$a0 = { badd0003d6b90300cd21eb04b44fcd217302eb9f8b84 }


condition:
	$a0
}