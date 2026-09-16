rule Win_Downloader_63760_1
{
strings:
	$a0 = { e80a000000e97affffffcccccccccc8bff558bec }

	$a1 = { 6262622e657865 }


condition:
	$a0 and $a1
}