rule Win_Trojan_Flex_3
{
strings:
	$a0 = { 0d242a2e636f6d002a2e657865002e2e00cd20008db67c038dbeb103b91c00a4e2fd8d96b103ffd2 }


condition:
	$a0
}