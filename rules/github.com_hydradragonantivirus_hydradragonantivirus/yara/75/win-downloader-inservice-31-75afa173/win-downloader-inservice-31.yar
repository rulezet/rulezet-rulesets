rule Win_Downloader_INService_31
{
strings:
	$a0 = { 73093130300d0a64096c6f63616c33097777772e64616c657863 }


condition:
	$a0
}