rule Win_Downloader_Small_1817
{
strings:
	$a0 = { 6eae2ad501b69207524c446f77f46cb8af3c544b8ded0e46c7687411703a2fc46c6966 }


condition:
	$a0
}