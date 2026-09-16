rule Win_Trojan_Kye_1
{
strings:
	$a0 = { 4150505920210d0a9a000088005589e531c09acd028800e8f3f9e8d9fbbf941c1e57bf961c1e57 }


condition:
	$a0
}