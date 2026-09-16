rule Win_Downloader_arc_1
{
strings:
	$a0 = { 526172211a0700cf907300000d000000[0-70]2e7064662e6578651621 }


condition:
	$a0
}