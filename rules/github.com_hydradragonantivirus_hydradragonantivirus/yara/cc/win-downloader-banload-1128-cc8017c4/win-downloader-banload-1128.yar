rule Win_Downloader_Banload_1128
{
strings:
	$a0 = { 9ef4d7d790a9f63c0d247bd5438f235a5005599a1d957c45adf06f28aaf992b2d6deda256f66cb234c14f90a5cdc2186033f65bc30ec315c47bdd9b0 }


condition:
	$a0
}