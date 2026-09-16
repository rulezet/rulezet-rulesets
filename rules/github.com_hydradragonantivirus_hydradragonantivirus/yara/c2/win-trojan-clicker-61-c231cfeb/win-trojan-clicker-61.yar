rule Win_Trojan_Clicker_61
{
strings:
	$a0 = { 558bec83c4f0b868864000e838c4ffff6a0068f486400068f886400068????????????8740006a00e8a3fcffff68f4010000e835f7ffffe8d4fcffffe84bb4ffff }


condition:
	$a0
}