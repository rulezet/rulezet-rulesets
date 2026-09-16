rule Win_Downloader_Small_2028
{
strings:
	$a0 = { 46c7687411703a2fc7d1616df4756e0f672e636f1f5e }


condition:
	$a0
}