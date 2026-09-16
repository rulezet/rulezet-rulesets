rule Win_Downloader_Small_2114
{
strings:
	$a0 = { ffd6e85c05000085c00f85340100005357bfc8104000eb0b }


condition:
	$a0
}