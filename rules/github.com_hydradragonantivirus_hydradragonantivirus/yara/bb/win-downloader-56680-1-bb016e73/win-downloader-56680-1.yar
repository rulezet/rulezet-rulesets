rule Win_Downloader_56680_1
{
strings:
	$a0 = { eb6c5589e583ec08c745f80000000060b828120000b9 }


condition:
	$a0
}