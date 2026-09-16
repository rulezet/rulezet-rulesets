rule Win_Downloader_Small_3407
{
strings:
	$a0 = { 37080a01763868748e703a2f207a61666a6c60641a71722e627d69fe75756ef5 }


condition:
	$a0
}