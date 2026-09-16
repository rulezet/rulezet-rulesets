rule Win_Downloader_Swizzor_266
{
strings:
	$a0 = { d9ee759ebd1938c1c7646ef6742229da1e967884d07a2db2a2cec8e4310ad61574ec4fdde8ee07b910c99fe1712a2b33 }


condition:
	$a0
}