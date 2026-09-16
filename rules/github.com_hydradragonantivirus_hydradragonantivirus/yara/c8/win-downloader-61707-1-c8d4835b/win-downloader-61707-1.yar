rule Win_Downloader_61707_1
{
strings:
	$a0 = { e805009572e905005eb8cccccccccccccccccccc8d42ff5bc38da424000000008d64240033c08a }


condition:
	$a0
}