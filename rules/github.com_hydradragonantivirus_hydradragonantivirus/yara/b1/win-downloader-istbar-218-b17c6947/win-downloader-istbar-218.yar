rule Win_Downloader_Istbar_218
{
strings:
	$a0 = { 4435327b73ff7799786d6c5f6973746261722e0a0f4953540b6fdbfb9d436c6f746368420a136e79677261bd5dfe }


condition:
	$a0
}