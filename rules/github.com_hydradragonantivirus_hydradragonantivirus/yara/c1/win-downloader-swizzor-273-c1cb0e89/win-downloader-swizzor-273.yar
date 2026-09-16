rule Win_Downloader_Swizzor_273
{
strings:
	$a0 = { 4144b362449ca572cf200801af67a931699b1a2f4b2f4efa0d243f769597e608c58e9677a6f1aeefeffd807cd5c87623 }


condition:
	$a0
}