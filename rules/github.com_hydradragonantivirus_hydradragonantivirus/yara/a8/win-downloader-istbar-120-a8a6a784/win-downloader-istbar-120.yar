rule Win_Downloader_Istbar_120
{
strings:
	$a0 = { d8feffff50e820fbffff8bf085f60f8c310300008b4dec57e80dfbffff8bf085f60f8c1e030000803f3d0f853d }

	$a1 = { 010002000300495354616374697665782e444c4c00446c6c4361 }


condition:
	$a0 and $a1
}