rule Win_Downloader_Small_5134
{
strings:
	$a0 = { 71eda146d86874e270383a2ff439616e7ed99c322ecbb36dff7e7fdb673abe0cc6625f6820f7d47570e3 }


condition:
	$a0
}