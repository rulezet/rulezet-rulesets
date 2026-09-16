rule Win_Downloader_Delf_972
{
strings:
	$a0 = { cc74297fb3f89742d133b8f4fc1aca0257d9a07b29abcb3635ce5741722987fcfb0ca81f2e7f30c49562deb2e20c77add0ac708ee443920179c4353b5b562932cbcfdaa90bad }


condition:
	$a0
}