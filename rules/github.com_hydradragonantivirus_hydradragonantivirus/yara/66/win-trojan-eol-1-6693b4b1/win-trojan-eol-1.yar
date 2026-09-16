rule Win_Trojan_EOL_1
{
strings:
	$a0 = "This ClamAV version has reached End of Life! Please upgrade to version 0.95 or later. For more information see  www.clamav.net/eol-clamav-094 and www.clamav.net/download"


condition:
	$a0
}