rule Win_Downloader_Small_3200
{
strings:
	$a0 = { 2104d63bbd95b2abd806225b2c95b03bbf0127ad281fcf8c9cc874677bca8fccca962a65bdc49d6b77c6b0e3243f8469a6c0846f3495b03beac3f96a3c1dfed6cd3661a764cd }


condition:
	$a0
}