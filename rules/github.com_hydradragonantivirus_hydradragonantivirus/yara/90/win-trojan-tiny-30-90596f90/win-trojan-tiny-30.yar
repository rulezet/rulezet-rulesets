rule Win_Trojan_Tiny_30
{
strings:
	$a0 = { a45eb44eba5b01cd21731287f7b8f3a4b901000e078945feb8fe0050c3b8023dba9e0052cd }


condition:
	$a0
}