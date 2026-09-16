rule Win_Downloader_462_1
{
strings:
	$a0 = { 81fe000000000f8fa0feffff33c1fff75f6a0889d381eac3d16e1f58e805000000480f4ac34f }


condition:
	$a0
}