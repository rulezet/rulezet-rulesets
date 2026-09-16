rule Win_Trojan_Parsit_2
{
strings:
	$a0 = { 0db440b985038bd681ea8602cd21721f }


condition:
	$a0
}