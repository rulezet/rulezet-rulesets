rule Win_Downloader_Small_1186
{
strings:
	$a0 = { 632e7068700064616272f6b7bfed616e2e067433696262073f6f6b3d007206fbfffff6676f6d193d31007c005552 }


condition:
	$a0
}