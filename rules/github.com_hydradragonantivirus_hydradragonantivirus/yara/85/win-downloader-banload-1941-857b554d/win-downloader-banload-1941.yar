rule Win_Downloader_Banload_1941
{
strings:
	$a0 = { 28241bd5169cda3a6c249c340720c1cbe6256c8e7cc24f85a38a6b3416cbd355c215512dffbc1bf717e1fed3e649e2a8bb28f45168475bd80fad6b08d1bd05b99ede7e075879bfec }


condition:
	$a0
}