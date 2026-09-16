rule Win_Downloader_77565_1
{
strings:
	$a0 = { 6875ae400054ff151881460089e74f8b3783c60185f6740881c0f66d9a1aebee }


condition:
	$a0
}