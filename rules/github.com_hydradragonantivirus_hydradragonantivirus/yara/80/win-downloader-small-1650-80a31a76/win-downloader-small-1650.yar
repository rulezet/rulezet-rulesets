rule Win_Downloader_Small_1650
{
strings:
	$a0 = { 0fdfd40f6fc0bae06a40000fd5dad9ce0fefe481e20000f0ffd9ca81c2007200008d0087c98cc987ff30c9dde4 }


condition:
	$a0
}