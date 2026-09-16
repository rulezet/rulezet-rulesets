rule Win_Trojan_Plastique_8
{
strings:
	$a0 = { b8404bcd213d78567512b8414bbf00 }


condition:
	$a0
}