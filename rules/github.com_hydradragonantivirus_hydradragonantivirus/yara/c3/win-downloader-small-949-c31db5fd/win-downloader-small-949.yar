rule Win_Downloader_Small_949
{
strings:
	$a0 = { 5c6c736572766963652e65786500000061746d5f6455524c3d687474703a2f2f }


condition:
	$a0
}