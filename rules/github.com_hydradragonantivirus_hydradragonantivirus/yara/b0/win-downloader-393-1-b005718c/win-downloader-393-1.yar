rule Win_Downloader_393_1
{
strings:
	$a0 = { 395db48d45c8508d8540ffffff74068d8560ffffff508d8550fbffff686040400050ff153030400083c410685c4040008d85e0fdffff50ffd78d85e0feffff508d85e0fdffff50ffd6 }


condition:
	$a0
}