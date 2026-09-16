rule Win_Downloader_63726_1
{
strings:
	$a0 = { 60be00e041008dbe0030feff5789e58d9c }

	$a1 = { 746865736563757265646f776e6c6f61642e636f6d }


condition:
	$a0 and $a1
}