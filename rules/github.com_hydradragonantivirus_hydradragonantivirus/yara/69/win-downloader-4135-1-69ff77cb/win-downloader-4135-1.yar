rule Win_Downloader_4135_1
{
strings:
	$a0 = { 2f636f646563735f7570646174652e65786522[0-36]3c2f4153583e }


condition:
	$a0
}