rule Win_Trojan_Hypervisor_4
{
strings:
	$a0 = { fefb061f2effae8efe33c08ed8812e1304040058 }


condition:
	$a0
}