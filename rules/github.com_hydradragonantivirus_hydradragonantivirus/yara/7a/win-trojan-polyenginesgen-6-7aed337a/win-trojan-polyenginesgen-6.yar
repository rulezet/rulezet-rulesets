rule Win_Trojan_PolyEngineSGen_6
{
strings:
	$a0 = { 0e1f07ba810be8211dba140de81b1dbf010bb009e8aa173c0875034feb0d3c0d740e3c3072ec3c3977e8aae8e21ceb }


condition:
	$a0
}