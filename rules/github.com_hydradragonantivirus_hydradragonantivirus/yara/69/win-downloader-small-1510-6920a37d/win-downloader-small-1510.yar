rule Win_Downloader_Small_1510
{
strings:
	$a0 = { 8964241468a4400010e83a060000e85bfaffff83c40483f8ff0f85e1feffff51 }


condition:
	$a0
}