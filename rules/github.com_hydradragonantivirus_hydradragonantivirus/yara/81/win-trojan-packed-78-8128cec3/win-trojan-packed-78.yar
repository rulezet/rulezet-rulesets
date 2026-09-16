rule Win_Trojan_Packed_78
{
strings:
	$a0 = { 60e8000000005b8d5bfabd000040008b7d3c8d743d008dbef80000000fb776064e }


condition:
	$a0
}