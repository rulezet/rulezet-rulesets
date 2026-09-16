rule Win_Downloader_6348_1
{
strings:
	$a0 = { 53683c30400056c7857cffffff44000000aae81d020000bf2c304000535756e810020000 }


condition:
	$a0
}