rule Win_Downloader_Small_2003
{
strings:
	$a0 = { 9c1440008b0350e86ffcffffffd06a05a12c2040005068b01440008b0650e858fcffffffd06a006a00a1302040 }


condition:
	$a0
}