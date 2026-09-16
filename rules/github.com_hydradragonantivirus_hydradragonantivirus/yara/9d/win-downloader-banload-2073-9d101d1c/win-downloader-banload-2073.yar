rule Win_Downloader_Banload_2073
{
strings:
	$a0 = { 6e164000f022f5dfeffb482c0000687474703a2f2f646c2d332e667265652f35b0000000323631 }


condition:
	$a0
}