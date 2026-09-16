rule Win_Downloader_Swizzor_313
{
strings:
	$a0 = { e1956824ade63663fbcd22928e4c0d8dfa31de6e6e28f3ec33d0584743837fc8a049d6a189bb901a9e086e567c0d4567 }


condition:
	$a0
}