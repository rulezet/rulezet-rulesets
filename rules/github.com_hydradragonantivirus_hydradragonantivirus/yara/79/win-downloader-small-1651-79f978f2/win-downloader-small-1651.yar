rule Win_Downloader_Small_1651
{
strings:
	$a0 = { 0fdbd1d9cdba70e848008d360febd881e20000f0ff89db0fefc80f6fdc }


condition:
	$a0
}