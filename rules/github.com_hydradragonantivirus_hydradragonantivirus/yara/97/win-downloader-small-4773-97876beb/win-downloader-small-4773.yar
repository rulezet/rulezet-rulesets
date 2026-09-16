rule Win_Downloader_Small_4773
{
strings:
	$a0 = { d9f08d6d00e8000000000fd5c05a0fefc08d0983ea0ad9ec89db0f6fd481b2270000001b09b5e78b9925778d0081aa370000006e67fb70f7378c010fefdc }


condition:
	$a0
}