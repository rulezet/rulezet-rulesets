rule Win_Downloader_Swizzor_303
{
strings:
	$a0 = { 334128bfd2b42fe70448c5b3341425093ee179cafd9ae61b87c3d89a10f2a11113014689dcd64b5f4b85fead183ed3d6 }


condition:
	$a0
}