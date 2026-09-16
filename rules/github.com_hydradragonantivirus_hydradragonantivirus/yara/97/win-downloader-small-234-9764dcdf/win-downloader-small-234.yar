rule Win_Downloader_Small_234
{
strings:
	$a0 = { 75747a2e6465003277456c64febbdf9e3363721c6f702e6e752f676f6675636b796f756ddfcede33656c661f464d64436c6f1055dbce5a }


condition:
	$a0
}