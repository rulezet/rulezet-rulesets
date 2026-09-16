rule Win_Downloader_Banload_991
{
strings:
	$a0 = { 4e6afab6dd95f29b75af3ad77f1e0dbd8adc78682504730ee5965b0855b6acfd77e25be0f4a397e881d6474dee11e3985e3ac00ec7276a7c3b9d94c207d884f940b7b4972c21e9f2e2e3d9ef3b8a6b1d }


condition:
	$a0
}