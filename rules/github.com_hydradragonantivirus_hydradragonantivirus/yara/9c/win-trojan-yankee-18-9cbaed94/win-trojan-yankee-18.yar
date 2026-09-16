rule Win_Trojan_Yankee_18
{
strings:
	$a0 = { 83c4049e7303e97a0233c933d2e811ffba0a00b91400e8fefe724f }


condition:
	$a0
}