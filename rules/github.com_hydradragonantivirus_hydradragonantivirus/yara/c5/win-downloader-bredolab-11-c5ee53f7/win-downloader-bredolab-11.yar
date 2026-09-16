rule Win_Downloader_Bredolab_11
{
strings:
	$a0 = { c1f70bc1fa02f6c2ae1afbc0c915d3c380ca74c0f903c0e10cfec00f86dffdff }


condition:
	$a0
}