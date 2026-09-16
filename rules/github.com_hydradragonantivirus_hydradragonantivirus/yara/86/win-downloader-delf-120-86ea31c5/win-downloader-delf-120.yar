rule Win_Downloader_Delf_120
{
strings:
	$a0 = { 7f204176656e676572206279204e68542f6a4045f7eeb923efb80809ef110fd48bd8ed702f8d4136dc6cbe0ab8e21c6b856fe92809c31fc894e014e1d9042feb }


condition:
	$a0
}