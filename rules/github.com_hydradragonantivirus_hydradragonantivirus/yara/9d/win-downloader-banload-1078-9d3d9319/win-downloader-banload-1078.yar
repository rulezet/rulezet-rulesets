rule Win_Downloader_Banload_1078
{
strings:
	$a0 = { 4845a41f3832229b0a05b83712eed1d8af7df1f94d7a60fffc012baa91b42a83a6eb1c136dfc054be252da4ab3d1e9845a1babf91f4ac124f01839632119661e4734bf9b }


condition:
	$a0
}