rule Win_Trojan_FormatC_90
{
strings:
	$a0 = { 6563686f[0-20]7c20666f726d617420633a203e206e756c }


condition:
	$a0
}