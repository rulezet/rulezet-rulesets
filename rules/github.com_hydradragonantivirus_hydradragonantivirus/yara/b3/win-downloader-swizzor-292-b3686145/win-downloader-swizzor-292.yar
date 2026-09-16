rule Win_Downloader_Swizzor_292
{
strings:
	$a0 = { 4ecdf41fe8335b70e4d29490b6204e5d3560428ac0018219bdbd41f8588cf3436bdc95c1c1c873a99ff063f9c71f38d7 }


condition:
	$a0
}