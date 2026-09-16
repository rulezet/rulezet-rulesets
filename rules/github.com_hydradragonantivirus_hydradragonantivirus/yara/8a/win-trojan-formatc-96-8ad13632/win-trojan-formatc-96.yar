rule Win_Trojan_FormatC_96
{
strings:
	$a0 = { 666f726d6174202f6175746f7465737420633a2f71 }


condition:
	$a0
}