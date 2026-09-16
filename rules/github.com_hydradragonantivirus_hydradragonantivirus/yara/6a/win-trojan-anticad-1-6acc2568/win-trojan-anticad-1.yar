rule Win_Trojan_AntiCAD_1
{
strings:
	$a0 = { b8404bcd213d78567512b8414bbf0001 }


condition:
	$a0
}