rule Win_Trojan_Hypervisor_3
{
strings:
	$a0 = { fefb061f2effae9bfe33c08ed8812e1304040058 }


condition:
	$a0
}