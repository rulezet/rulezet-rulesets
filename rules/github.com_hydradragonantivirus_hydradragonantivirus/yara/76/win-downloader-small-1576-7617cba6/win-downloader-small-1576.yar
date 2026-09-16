rule Win_Downloader_Small_1576
{
strings:
	$a0 = { c833c083e103f3a4bfb410400083c9fff2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca8d85acfbffff83e10350f3a4e88ce6ffff }


condition:
	$a0
}