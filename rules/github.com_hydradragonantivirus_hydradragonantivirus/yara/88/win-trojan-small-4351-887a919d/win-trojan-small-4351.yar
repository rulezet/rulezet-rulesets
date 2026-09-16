rule Win_Trojan_Small_4351
{
strings:
	$a0 = { 89c689c381c000bcbffff7d85003342450 }


condition:
	$a0
}