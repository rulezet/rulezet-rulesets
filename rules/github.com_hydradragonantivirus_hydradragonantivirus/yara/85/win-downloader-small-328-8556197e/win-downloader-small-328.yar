rule Win_Downloader_Small_328
{
strings:
	$a0 = { 46e4c9ea79f9bace118c8200aa004ba90be3c9ea79f9bace118c8200aa004ba90bc1c9ea79f9bace118c8200aa004ba90b69636f6f3a2f2f0069636f6f6c6f6164 }


condition:
	$a0
}