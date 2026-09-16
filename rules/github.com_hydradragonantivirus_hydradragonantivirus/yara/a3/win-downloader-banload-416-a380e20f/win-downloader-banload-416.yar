rule Win_Downloader_Banload_416
{
strings:
	$a0 = { 787c37000000ffffffff090000005c666f746f2e6a7067000000ffffffff08000000666f746f2e6a706700000000ffffffff4200 }


condition:
	$a0
}