rule Win_Downloader_Small_3212
{
strings:
	$a0 = { f0c595706fbb413c173c7fe163dab5f7ade1bc61b71abf70a82c4d72e2258d76fa2fbf575759d8bf6a274c76e036ad54f2553097fb61525399074c7663d1bce4fb2f4c55fc01 }


condition:
	$a0
}