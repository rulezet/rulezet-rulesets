rule Win_Downloader_10104_1
{
strings:
	$a0 = { 68c4ca400068b0ca40008d8d44faffffe801001c1d508d8540faffff50e8010060b2 }


condition:
	$a0
}