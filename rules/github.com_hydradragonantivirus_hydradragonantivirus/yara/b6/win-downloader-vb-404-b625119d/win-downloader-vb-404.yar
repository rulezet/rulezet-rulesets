rule Win_Downloader_VB_404
{
strings:
	$a0 = { 2d7faa74e3e202d759435788c8b7c66ed08efe05e71cc62abdd4453d549bd6f0753ca00bfb9681f824abf39680e1045f636ce7b207e7976e84e9ee57e7af912449 }


condition:
	$a0
}