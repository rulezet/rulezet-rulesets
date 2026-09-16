rule Win_Trojan_Brolux_1
{
strings:
	$a0 = { 6c757875727962726f2e636f2e6b72 }

	$a1 = { 6661732d676f2d6a702d7365637572697479 }


condition:
	$a0 and $a1
}