rule Win_Downloader_Delf_902
{
strings:
	$a0 = { 648920b8e4584000ba5c354000e863e9ffffb8e0584000ba98354000e854e9ffff68c85640006804010000e879efffff }


condition:
	$a0
}