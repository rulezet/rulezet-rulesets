rule Win_Trojan_Sinowal_47
{
strings:
	$a0 = { 8d85b8f9ffff50ffd78d85b4f8ffff508d85bcfaffff50ffd668902140008d85bcfaffff50ffd7e800000a2685c075148d85bcfaffff50e8000007d43d3104000059755a }


condition:
	$a0
}