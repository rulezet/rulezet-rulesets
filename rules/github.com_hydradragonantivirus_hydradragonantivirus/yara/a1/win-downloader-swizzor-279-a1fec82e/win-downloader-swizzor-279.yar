rule Win_Downloader_Swizzor_279
{
strings:
	$a0 = { d76f47a8916f27d4064b5ca69767a0092b767a9c4595f6da06119cc8690a1a572dc643cc691eae4352e26b1b8d3ecfeb }


condition:
	$a0
}