rule Win_Downloader_60771_1
{
strings:
	$a0 = { b825000000e87f0000003d000000c07f2a51eb0db8ffffffff83e80329c249eb2889d7f30f }


condition:
	$a0
}