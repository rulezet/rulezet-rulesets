rule Win_Downloader_3737_1
{
strings:
	$a0 = { 6a00a170664000e87df5ffff50b870664000e86ef6ffff50a16c66400050e80efcffffb8ff7f0000e8fce3ffff8bd885db0f8471020000 }


condition:
	$a0
}