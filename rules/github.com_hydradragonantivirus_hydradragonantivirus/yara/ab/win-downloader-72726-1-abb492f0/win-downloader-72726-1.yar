rule Win_Downloader_72726_1
{
strings:
	$a0 = { 81ec8001000053555633 }

	$a1 = { 7265725c517569636b204c61756e6368 }

	$a2 = { 5c54656d70 }

	$a3 = { 6e7673322e696e66 }

	$a4 = { 6172655c66636e }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}