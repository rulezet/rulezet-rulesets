rule Win_Downloader_Delf_529
{
strings:
	$a0 = { e84cfcffffbae43b4000b8f83b4000e80dfeffff6a01681c3c4000e8edfcffffe88cf6ffff }


condition:
	$a0
}