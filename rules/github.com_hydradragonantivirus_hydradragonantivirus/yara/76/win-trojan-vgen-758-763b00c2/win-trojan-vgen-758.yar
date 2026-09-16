rule Win_Trojan_VGEN_758
{
strings:
	$a0 = { 4040a3c000b440b9e40133d2e8bd00b000e8b200b440b90500babf00e8b600b43ee8b1001f }


condition:
	$a0
}