rule Win_Trojan_Nexiv_Der_2
{
strings:
	$a0 = { eb96ee94ecd5eebb82fe149e96948f5fc6cbcff2f0fffbae }


condition:
	$a0
}