rule Win_Downloader_67971_1
{
strings:
	$a0 = { 558bec6aff68d8d340006810bb400064a1 }

	$a1 = { 3b3c3437312652222722393b3c52352737212652 }


condition:
	$a0 and $a1
}