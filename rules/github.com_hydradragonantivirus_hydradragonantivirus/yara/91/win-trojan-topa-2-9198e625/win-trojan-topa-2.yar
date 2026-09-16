rule Win_Trojan_Topa_2
{
strings:
	$a0 = { 5f81ef03018bf781c71e01b9b9080e1f8a0534fffec0880547e2f5b04870be33dfc3 }


condition:
	$a0
}