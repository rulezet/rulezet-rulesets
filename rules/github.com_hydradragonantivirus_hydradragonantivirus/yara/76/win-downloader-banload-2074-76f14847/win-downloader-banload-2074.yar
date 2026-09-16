rule Win_Downloader_Banload_2074
{
strings:
	$a0 = { 3f3c62407fd20f3f027b8bc94723d0fa1c386f00a185dd2c4000f022eabfdff790580000687474703a2f2f646c2d312e667265652f3532 }


condition:
	$a0
}