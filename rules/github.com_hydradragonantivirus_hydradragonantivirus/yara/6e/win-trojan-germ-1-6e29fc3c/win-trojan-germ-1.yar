rule Win_Trojan_Germ_1
{
strings:
	$a0 = { 505352b8023dcd210e1f93b80057cd215152bafa01b905 }


condition:
	$a0
}