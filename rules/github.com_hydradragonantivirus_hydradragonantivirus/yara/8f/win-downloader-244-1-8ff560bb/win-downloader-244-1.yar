rule Win_Downloader_244_1
{
strings:
	$a0 = { c8093fbf6e360770682e0120726673babe76e8627e6e1c6c636a9d693fb86bfaca0e6593313c6264c2d8ddf6203c756eee20d78706afaf617c }


condition:
	$a0
}