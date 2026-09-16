rule Win_Trojan_MiniParg_1
{
strings:
	$a0 = { 6e69506967206279205b57617247616d652c23656f665d0000002a2e4558 }


condition:
	$a0
}