rule Win_Downloader_10606_1
{
strings:
	$a0 = { 87db9050589690969090bf111040009087c99090 }


condition:
	$a0
}