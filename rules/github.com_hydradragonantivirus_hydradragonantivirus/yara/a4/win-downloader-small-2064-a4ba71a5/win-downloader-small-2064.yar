rule Win_Downloader_Small_2064
{
strings:
	$a0 = { 68748e703a2f2e75a664613a362e6d343072737b66f5e3bfc52f3e347a1e3a }


condition:
	$a0
}