rule Win_Downloader_63712_1
{
strings:
	$a0 = { 5c43757272656e7456657273696f6e5c52756e }

	$a1 = { 5c7379736d6f6e2e657865 }

	$a2 = { 5c73797366696e642e657865 }


condition:
	$a0 and $a1 and $a2
}