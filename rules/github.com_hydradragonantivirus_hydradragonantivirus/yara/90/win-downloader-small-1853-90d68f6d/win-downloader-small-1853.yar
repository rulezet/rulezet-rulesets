rule Win_Downloader_Small_1853
{
strings:
	$a0 = { 89c087ffbaffffffffda142442d9f081c200f20000d9f1dde1 }


condition:
	$a0
}