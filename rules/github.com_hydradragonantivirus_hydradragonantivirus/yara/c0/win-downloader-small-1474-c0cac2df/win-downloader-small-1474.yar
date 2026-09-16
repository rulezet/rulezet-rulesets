rule Win_Downloader_Small_1474
{
strings:
	$a0 = { 6d3d62693e2e3f787039588d14025334800b5c6d73637361a617397002b4bdb873f857c6b20c03 }


condition:
	$a0
}