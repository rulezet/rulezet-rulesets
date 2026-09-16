rule Win_Trojan_VGEN_765
{
strings:
	$a0 = { 521fe800005d8d862b000e508f060c008f060e0083c603565f0e1fb9e102b8b838a30001b01ba20201cc0bc975 }


condition:
	$a0
}