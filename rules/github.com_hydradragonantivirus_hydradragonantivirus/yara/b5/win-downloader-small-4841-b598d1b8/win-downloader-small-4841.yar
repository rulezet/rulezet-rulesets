rule Win_Downloader_Small_4841
{
strings:
	$a0 = { bfb410400083c9ff33c0baf8354000f2aef7d12bf9538bc18bf78bfac1e902 }


condition:
	$a0
}