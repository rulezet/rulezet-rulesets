rule Win_Downloader_Banload_593
{
strings:
	$a0 = { 6acb86c8f77d395e945d164b14a69ecff842a547ef9f8c0f68d86a128fe44847ccfe16320fa6db23828fb7e83b48aa8f67ea589dc6c522477ee643dbb4c5562d7e75cfdb }


condition:
	$a0
}