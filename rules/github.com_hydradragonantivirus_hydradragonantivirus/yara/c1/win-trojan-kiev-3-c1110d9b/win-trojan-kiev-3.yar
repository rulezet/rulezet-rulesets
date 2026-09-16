rule Win_Trojan_Kiev_3
{
strings:
	$a0 = { d381c2fbff8bdfb440cd215b720053 }


condition:
	$a0
}