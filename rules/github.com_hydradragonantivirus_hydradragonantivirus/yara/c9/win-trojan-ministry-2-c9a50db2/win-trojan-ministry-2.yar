rule Win_Trojan_Ministry_2
{
strings:
	$a0 = { e80a00bed40103360601ffe600be1501033606018a24 }


condition:
	$a0
}