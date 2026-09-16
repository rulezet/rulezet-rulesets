rule Win_Trojan_DIW_9
{
strings:
	$a0 = { e93d002a2e636f6d00eb340080002a2e64626600636c69703f3f3f3f2e2a003f6c696e6b2e2a002a2e6f626a00 }


condition:
	$a0
}