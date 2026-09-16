rule Win_Downloader_Small_1730
{
strings:
	$a0 = { 89edbae06a40000fefdb81e20000f0ffd9ca0febda81c2007200008d6d000fd5c48cc9d9ff }


condition:
	$a0
}