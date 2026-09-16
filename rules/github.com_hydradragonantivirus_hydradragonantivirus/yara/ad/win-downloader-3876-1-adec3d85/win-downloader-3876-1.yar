rule Win_Downloader_3876_1
{
strings:
	$a0 = { 64ffffffba23000000e8bb7ffeffc3e9b979feffebd85f5e5be8977efeff000000ffffffff14000000687474703a2f2f7777772e62616964752e63 }


condition:
	$a0
}