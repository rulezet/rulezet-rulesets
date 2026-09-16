rule Win_Trojan_Tiny_38
{
strings:
	$a0 = { 3e8a010574238b0e8a01010e8b0180068b0101ba9e00b8013dcd218bd8b440b98c00ba0001cd21 }


condition:
	$a0
}