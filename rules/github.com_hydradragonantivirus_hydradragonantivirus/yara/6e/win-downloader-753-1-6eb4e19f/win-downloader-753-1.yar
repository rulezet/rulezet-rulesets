rule Win_Downloader_753_1
{
strings:
	$a0 = { 8d3dff27df0781efff65890789fe8d9f7c04fe7f81eb0000fe7f6a006aff6a006833030000ff15f8c6550005f9df23bf0304240107c1 }


condition:
	$a0
}