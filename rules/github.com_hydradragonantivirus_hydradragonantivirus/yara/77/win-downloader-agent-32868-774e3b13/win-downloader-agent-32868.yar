rule Win_Downloader_Agent_32868
{
strings:
	$a0 = { c53c9f12c83d8eb1b3484250ad737b42c0eae3f52ce9ca598ba73c0e5c83f35666d63e7c1f1e28d44ed2e316642ffedd64cb930898e5971bb2129db48c35 }


condition:
	$a0
}