rule Win_Downloader_Small_1188
{
strings:
	$a0 = { 54646863702ddc4fe910b42418bbcc4c5785d952fed097bd65580e53594254454db324be40e98f7c6c53705e99f2af7e7b846b }


condition:
	$a0
}