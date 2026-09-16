rule Win_Trojan_FormatC_51
{
strings:
	$a0 = { 40666f726d617420633a0d0a6175746f746573742f666f726d6174 }


condition:
	$a0
}