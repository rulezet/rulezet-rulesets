rule Win_Downloader_4467_1
{
strings:
	$a0 = { 52494646????????41434f4e616e69 }

	$a1 = { 636d64203e }

	$a2 = { 7474703a2f2f }


condition:
	$a0 and $a1 and $a2
}