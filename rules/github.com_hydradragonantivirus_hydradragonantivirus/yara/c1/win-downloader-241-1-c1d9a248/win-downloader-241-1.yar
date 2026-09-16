rule Win_Downloader_241_1
{
strings:
	$a0 = { 6a0168f4364000e8d1fdffffb870564000ba6c374000e8f6f8ffff }


condition:
	$a0
}