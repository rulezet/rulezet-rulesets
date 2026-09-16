rule Win_Downloader_68062_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f6 }

	$a1 = { 6173686d616973762e657865 }


condition:
	$a0 and $a1
}