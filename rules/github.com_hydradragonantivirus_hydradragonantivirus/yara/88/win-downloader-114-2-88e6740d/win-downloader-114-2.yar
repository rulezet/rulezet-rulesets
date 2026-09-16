rule Win_Downloader_114_2
{
strings:
	$a0 = { f9728e4ba2db64feba6471bb6a50a1b32f0c8cc155748e4ba6db64d6ba6471bb6a50cdf9efd8703eaa24fa7b567b2f6563e724b546a59d7ea324716dfc7342e51313733eaa17b1b317e587c155acecfe5cdb }


condition:
	$a0
}