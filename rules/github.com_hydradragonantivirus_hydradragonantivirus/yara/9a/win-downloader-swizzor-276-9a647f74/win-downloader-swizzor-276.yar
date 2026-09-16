rule Win_Downloader_Swizzor_276
{
strings:
	$a0 = { 0a966588af66f1f457a3f62e161398e9e158207f209bc3d656a639d36d759fd3795176500b95478d91a1d752c5ad11c1 }


condition:
	$a0
}