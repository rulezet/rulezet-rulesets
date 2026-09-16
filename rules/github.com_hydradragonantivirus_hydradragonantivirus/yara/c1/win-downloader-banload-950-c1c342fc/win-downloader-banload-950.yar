rule Win_Downloader_Banload_950
{
strings:
	$a0 = { 2a885da6a7f5f213d7dd99e49e8e800ad92d7dd5df7381f59d78495bfadc16f1d3cd25d6319134469a7a341fe5033c39a3a011ccd135c0542ec037104c183f7275627d60cb726fbdda0c97d13bbf }


condition:
	$a0
}