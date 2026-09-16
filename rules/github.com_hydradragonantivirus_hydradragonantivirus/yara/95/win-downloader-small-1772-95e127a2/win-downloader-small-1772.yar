rule Win_Downloader_Small_1772
{
strings:
	$a0 = { 65000000ffffffff0900000063737273732e657865000000ffffffff0c000000466972657761 }


condition:
	$a0
}