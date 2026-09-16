rule Win_Downloader_272_1
{
strings:
	$a0 = { 646a1b252b25a9a996e49f8fcd9d2efded42ded2696fa9932fd28d7ecdcbcdcdcbeec92729908878c7f396a425cb433404c0d325822a90c31feb7c2e3edd3ebd3c1fab81a082b9b9b687dab09415 }


condition:
	$a0
}