rule Win_Downloader_Small_3366
{
strings:
	$a0 = { 7a2e636e2f63732e657865ca5e7e913c633a5c636669672a7e3b6cb6006377002e6c6f7665b914f6df036f6b2e6e65742f }


condition:
	$a0
}