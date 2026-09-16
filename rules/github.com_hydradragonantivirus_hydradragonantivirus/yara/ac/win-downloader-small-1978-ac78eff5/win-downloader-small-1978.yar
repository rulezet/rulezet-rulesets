rule Win_Downloader_Small_1978
{
strings:
	$a0 = { 687488703a2fe3e8796d31616e3c632ec96fe7f369e367 }


condition:
	$a0
}