rule Win_Trojan_ShyDemon_2
{
strings:
	$a0 = { 8b8649078d9e3801b9e802902e31074343e2f958595bc3 }


condition:
	$a0
}