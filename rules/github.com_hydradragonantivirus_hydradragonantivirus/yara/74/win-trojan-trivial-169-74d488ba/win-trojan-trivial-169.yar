rule Win_Trojan_Trivial_169
{
strings:
	$a0 = { cd21720f93b440ba0001b95601cd21b4 }


condition:
	$a0
}