rule Win_Downloader_7718_1
{
strings:
	$a0 = { 68e27e400064ff30648920b8a8974000baf87e4000e893b7ffffba??7f4000a1a8974000e89cfeffff84c0740c6a0068??7f4000e87cc6ffff }


condition:
	$a0
}