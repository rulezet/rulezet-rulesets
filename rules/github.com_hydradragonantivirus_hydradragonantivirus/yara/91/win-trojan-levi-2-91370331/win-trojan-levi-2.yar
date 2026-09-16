rule Win_Trojan_Levi_2
{
strings:
	$a0 = { b8ffbbcd213dbbff74608cd8488ec026803e00005a7402eb51 }


condition:
	$a0
}