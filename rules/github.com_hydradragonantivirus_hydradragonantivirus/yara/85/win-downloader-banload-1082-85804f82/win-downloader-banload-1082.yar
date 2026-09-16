rule Win_Downloader_Banload_1082
{
strings:
	$a0 = { 481cb83435aae32b5e35aca841a983bafcd4015324bd014f41ab3cabab2dbbe9f4c88650e9493f11328fbea9764963397a634920e1fc27 }


condition:
	$a0
}