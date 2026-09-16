rule Win_Downloader_Small_1812
{
strings:
	$a0 = { b16874c4703a712f6777022ef764216e3231de878174fdf48a18785f1136206e53663d }


condition:
	$a0
}