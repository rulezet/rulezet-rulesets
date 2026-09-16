rule Win_Downloader_Small_1327
{
strings:
	$a0 = { 6c507598711c2e7068923f5827205c6d3f73316ea454747c2a686fcfc21070617987 }


condition:
	$a0
}