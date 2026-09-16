rule Win_Trojan_SillyC_71
{
strings:
	$a0 = { 030089450bb440ba5dff01fab1aecd21b8004231c931d2 }


condition:
	$a0
}