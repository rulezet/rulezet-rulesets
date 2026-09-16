rule Win_Downloader_Small_3191
{
strings:
	$a0 = { a93cbb7136426f3d4ec551e03a239bf6f4189260eee39171f1d56373bbdca377a3d691560ea0f6be33de6277b9cf8355abac1e96a2987c52c0fe62773a2892e5a2d66254a5f8 }


condition:
	$a0
}