rule Win_Downloader_Small_1495
{
strings:
	$a0 = { 2f636a7b0c6a67736677736db7b783fd68646c70621953792f656d73076f66dbefdaff }


condition:
	$a0
}