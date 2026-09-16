rule Win_Trojan_Cpw_2
{
strings:
	$a0 = { c0fa26c70684001802268c1e8600fbb81635cd21891e61008c06630033c08ec0fa26c70658 }


condition:
	$a0
}