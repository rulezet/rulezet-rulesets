rule Win_Downloader_Small_1977
{
strings:
	$a0 = { b16874c4703a712ff479186d616e3c632ee46ff3f969f167d175f7796cde807f }


condition:
	$a0
}