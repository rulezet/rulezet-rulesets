rule Win_Downloader_3877_1
{
strings:
	$a0 = { 558bec83c4f0b8a83f1413e80cf8ffffb8f4401413e892faffff84c074156810411413e870f8ffff }


condition:
	$a0
}