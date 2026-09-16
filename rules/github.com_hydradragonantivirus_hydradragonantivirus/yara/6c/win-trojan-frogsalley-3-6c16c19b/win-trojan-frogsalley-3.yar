rule Win_Trojan_FrogsAlley_3
{
strings:
	$a0 = { 0105000126a31500268c1e130026c706 }


condition:
	$a0
}