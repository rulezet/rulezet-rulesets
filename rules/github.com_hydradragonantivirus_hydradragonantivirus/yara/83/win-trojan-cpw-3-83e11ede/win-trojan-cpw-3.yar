rule Win_Trojan_Cpw_3
{
strings:
	$a0 = { 8ec0fa26c70684001b02268c1e8600fbb81635cd21891e61008c06630033c08ec0fa26c70658 }


condition:
	$a0
}