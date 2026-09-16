rule Win_Downloader_103788_1
{
strings:
	$a0 = { 5589e583ec2053ff35[0-20]6a6a6a6a[0-20]6a6a6a6a }


condition:
	$a0
}