rule Win_Trojan_USSR_31
{
strings:
	$a0 = { 83fce072f62ec7470712002ec7470900 }


condition:
	$a0
}