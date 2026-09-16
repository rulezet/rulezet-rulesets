rule Win_Trojan_Downloader_57
{
strings:
	$a0 = { 617a2e676f332e696370636e2e636f6d2f312e6a73223e3c2f7363726970743e }


condition:
	$a0
}