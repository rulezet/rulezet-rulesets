rule Win_Downloader_Banload_983
{
strings:
	$a0 = { 1b850c955a1e312b25cb8af240a5d22ca510c54f425b17d32593315e79ff40c6172c5c0bf971d6c73cd08eb698f49d673de747ad90b863c7d271a2dc0f6443f56a3f5ccfadd0b0b307f889aece60 }


condition:
	$a0
}