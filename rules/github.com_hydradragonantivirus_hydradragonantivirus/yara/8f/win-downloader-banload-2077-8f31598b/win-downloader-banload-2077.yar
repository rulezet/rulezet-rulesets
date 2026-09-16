rule Win_Downloader_Banload_2077
{
strings:
	$a0 = { eb02eb02eb0190e9e4020000bf1e1240008bf7b9ce020000ac320500104000aae2f61d00f7 }


condition:
	$a0
}