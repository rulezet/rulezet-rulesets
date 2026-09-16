rule Win_Downloader_Banload_414
{
strings:
	$a0 = { 6ecf20d8dd09c629b11723137dfff56e2e0f5168e3703a2f2f6379746f47a69e7deb2e566d2e052ee186ddfe62722f64696161062f6672132e5bdc7bba611f5c6c }


condition:
	$a0
}