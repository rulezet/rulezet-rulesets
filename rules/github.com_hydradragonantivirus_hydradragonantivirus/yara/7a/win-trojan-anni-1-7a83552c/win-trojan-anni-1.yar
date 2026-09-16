rule Win_Trojan_Anni_1
{
strings:
	$a0 = { 8db62701568b96f201b960008bfefcad33c2abe2fac3 }


condition:
	$a0
}