rule Win_Trojan_Zbot_1350
{
strings:
	$a0 = { bb782b3782635ee75740bf46a668936d9ab17da2fecf0c01 }


condition:
	$a0
}