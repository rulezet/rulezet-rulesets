rule Win_Downloader_Small_4766
{
strings:
	$a0 = { 707b7a753e32396b7d796d7477776b7b3670746b7332716a00 }


condition:
	$a0
}