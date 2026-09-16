rule Win_Downloader_Small_1378
{
strings:
	$a0 = { 68c833c3e961c28debf85d8a89832d1f1e01a93890f9f21c34e01184438ac81c63687488703a2fe2353d347a }


condition:
	$a0
}