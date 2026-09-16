rule Win_Trojan_Tiny_5
{
strings:
	$a0 = { 69f3a45eb44eba6301cd21731287f7b8f3a4b901000e078945feb8fe0050c3b8023dba9e0052cd }


condition:
	$a0
}