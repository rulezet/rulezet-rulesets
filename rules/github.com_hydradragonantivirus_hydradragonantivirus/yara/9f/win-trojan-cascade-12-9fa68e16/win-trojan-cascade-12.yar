rule Win_Trojan_Cascade_12
{
strings:
	$a0 = { f6872a0101740f8db74d01ba820631343114464a75f8 }


condition:
	$a0
}