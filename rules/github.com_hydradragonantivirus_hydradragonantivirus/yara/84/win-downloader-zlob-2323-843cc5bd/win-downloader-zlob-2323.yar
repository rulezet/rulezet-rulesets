rule Win_Downloader_Zlob_2323
{
strings:
	$a0 = { 0b848527af38e549fa837cf10457264a902cb23f74768780872c262d2c51c0f5ceb1a9d2b356c0a6ce4f3243aa3b9d50320d }


condition:
	$a0
}