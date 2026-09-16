rule Win_Downloader_Banload_43
{
strings:
	$a0 = { b8b8984000ba9c7f4000e8d4b7ffffb8b0984000e876b7ffffb8a49840008b15b8984000e8bab7ffffa1a4984000e8d0b9ffff8bd885db7e2dbe01000000 }


condition:
	$a0
}