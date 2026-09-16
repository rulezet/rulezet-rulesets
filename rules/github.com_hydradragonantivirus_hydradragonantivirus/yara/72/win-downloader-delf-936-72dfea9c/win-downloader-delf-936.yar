rule Win_Downloader_Delf_936
{
strings:
	$a0 = { b8e4a54100e862e4feff8b55a4b864ca4100e825a3feff6a00681ca64100e889c2feff85c00f950590c84100 }


condition:
	$a0
}