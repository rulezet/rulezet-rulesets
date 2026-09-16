rule Win_Downloader_672_1
{
strings:
	$a0 = { 686c4040008d8544fbffff50ffd6395d????8520ffffff74068d85??ffffff508d????fbffff50ffd768644040008d8544fbffff50ffd78d45 }

	$a1 = { 25750000633a0000633a5c002f0000002f70726f67732f0068747470 }


condition:
	$a0 and $a1
}