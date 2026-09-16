rule Win_Downloader_VB_406
{
strings:
	$a0 = { f9df8d94ad64ce946d3d83aafda9bf1b186cc1582d164bd743710cd6671a5f1f7a11c8041dde58de802f83c00258bdc39b4dbcec363e4299fedd5dd147470ce140 }


condition:
	$a0
}