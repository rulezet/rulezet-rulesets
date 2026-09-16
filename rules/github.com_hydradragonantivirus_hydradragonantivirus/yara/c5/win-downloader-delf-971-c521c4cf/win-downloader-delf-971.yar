rule Win_Downloader_Delf_971
{
strings:
	$a0 = { d969db4b8ab7c299147bad87b052ae35a48e0923156fff2f2e4568a7603bf14857e1874f0e151c70cda623f60c5b81ab8c28dec2b3fc784f80d94fafcf83ad8d180e6c93c7d5 }


condition:
	$a0
}