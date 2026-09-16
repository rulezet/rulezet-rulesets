rule Win_Downloader_Banload_990
{
strings:
	$a0 = { 6aa214968d0bb4891994e2267cdc9bd57edc77ba1d0082dab63e16e2ca09902f364fcf37c80371c0c1fd2c9ffb37e99ffc46f2d9efa77c280d3279368e65bc29b8632417071345db47c77b3ea17f6a59 }


condition:
	$a0
}