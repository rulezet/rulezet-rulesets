rule Win_Downloader_56898_1
{
strings:
	$a0 = { 1ed391b131ffdfffff35a552b39355964dd2b597f7853609eba8aed9ea8bac0dab888d2d4e2ff83ffcff8762806400a38765dca484445ca517c7675b3ebd995939ffffffff93f174f6987d1fff45bf1e }


condition:
	$a0
}