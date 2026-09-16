rule Win_Downloader_VB_401
{
strings:
	$a0 = { 2ff01783e9f5428b92315aba80233db8ed5e337f37223b27eb4d9af5865b06ba5bdc733053f0bcb6869030673da2cf37020f325e3f204722c8b1fbea843768c16e }


condition:
	$a0
}