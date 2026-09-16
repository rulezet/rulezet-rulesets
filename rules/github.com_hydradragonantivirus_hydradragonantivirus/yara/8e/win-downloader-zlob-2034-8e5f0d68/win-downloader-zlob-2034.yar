rule Win_Downloader_Zlob_2034
{
strings:
	$a0 = { c3faaac6f04bd0add69f0bd7444d62ad24eafed1066e7420a86210205ee0f7d97476e32eb52c471692cb392b3ddc4a6365c6 }


condition:
	$a0
}