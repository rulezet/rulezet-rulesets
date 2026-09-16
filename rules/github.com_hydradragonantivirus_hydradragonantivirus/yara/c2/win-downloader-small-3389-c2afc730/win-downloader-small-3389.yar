rule Win_Downloader_Small_3389
{
strings:
	$a0 = { b892694b9170b173386a86e4907f6ed1ae7ec168d4d09e1a7a8ef35cd1445d7300cf824da6e7758e60c549b3b690d34a034d9dbeba35b387096c8b6f23e50301d1afa26e1d }


condition:
	$a0
}