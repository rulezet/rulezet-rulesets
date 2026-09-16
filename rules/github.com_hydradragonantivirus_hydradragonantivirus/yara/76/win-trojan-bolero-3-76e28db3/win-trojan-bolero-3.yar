rule Win_Trojan_Bolero_3
{
strings:
	$a0 = { bf390003fdb2012e30152e280d9090902e281547e2f1 }


condition:
	$a0
}