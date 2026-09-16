rule Win_Downloader_VB_814
{
strings:
	$a0 = { 83c40cba441a40008d4de4ffd7bae41940008d4de8ffd78b168d45e0508d4de48d45e8515056ff92f8060000 }


condition:
	$a0
}