rule Win_Downloader_Agent_31788
{
strings:
	$a0 = { ff0588594200a18859420048743048740a4875406858d94100eb05 }


condition:
	$a0
}