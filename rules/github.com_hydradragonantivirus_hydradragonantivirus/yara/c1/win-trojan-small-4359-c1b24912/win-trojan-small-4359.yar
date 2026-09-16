rule Win_Trojan_Small_4359
{
strings:
	$a0 = { 89c689c381c000e4bdfff7d85003342450 }


condition:
	$a0
}