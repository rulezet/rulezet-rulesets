rule Win_Downloader_Small_921
{
strings:
	$a0 = { 58259ff0bc400ec8f888250c1f0a083397b40060b4ab83b193451043effeff5f2f706172746e65723a61 }


condition:
	$a0
}