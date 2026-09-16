rule Win_Trojan_Bancos_665
{
strings:
	$a0 = { d5c87d3b598a23d3f9c5e441d69e1a8fa80b91df1481001f6eff06d577355326b011ab9d608615d38d31e308f6c75f6aaab592acfdb4ab929ed3484337a4f3469674e3fd }


condition:
	$a0
}