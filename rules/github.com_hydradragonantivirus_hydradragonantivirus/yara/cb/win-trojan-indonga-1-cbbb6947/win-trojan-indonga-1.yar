rule Win_Trojan_Indonga_1
{
strings:
	$a0 = { ad1ba61445d9004aefd635380d05740d89f517720defea30 }


condition:
	$a0
}