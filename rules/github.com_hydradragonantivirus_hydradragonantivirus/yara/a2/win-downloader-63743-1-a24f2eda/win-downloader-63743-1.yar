rule Win_Downloader_63743_1
{
strings:
	$a0 = { 558becb9080000006a006a004975f95153b8887e4000e88d }

	$a1 = { 5e6e6574776f726b5f6e657773 }


condition:
	$a0 and $a1
}