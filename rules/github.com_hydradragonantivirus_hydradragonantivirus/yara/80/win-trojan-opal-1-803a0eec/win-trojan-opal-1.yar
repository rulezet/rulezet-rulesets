rule Win_Trojan_Opal_1
{
strings:
	$a0 = { 83c31f8b178bdf83c302b91b008b0733c2890743e2f7c3 }


condition:
	$a0
}