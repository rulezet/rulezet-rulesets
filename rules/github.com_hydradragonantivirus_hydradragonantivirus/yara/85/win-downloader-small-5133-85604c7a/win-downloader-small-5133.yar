rule Win_Downloader_Small_5133
{
strings:
	$a0 = { 75416a006a016803204000ff35300f4500e89004000083f8ff74288b5d08 }


condition:
	$a0
}