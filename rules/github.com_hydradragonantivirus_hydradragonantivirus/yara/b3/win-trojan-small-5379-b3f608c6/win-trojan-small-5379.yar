rule Win_Trojan_Small_5379
{
strings:
	$a0 = { e8000000005833c7e80000000083c404 }


condition:
	$a0
}