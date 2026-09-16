rule Win_Trojan_Avcs_3
{
strings:
	$a0 = { e800005b81eb????8beb8db6????568b96????b97a008bfe84fffcad33c2ab84d8e2f8c3 }


condition:
	$a0
}