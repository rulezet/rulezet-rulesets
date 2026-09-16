rule Win_Downloader_Agent_35050
{
strings:
	$a0 = { c03c476d832c59122de0354ed4cf609563715ba98f142704ec5ad0b56bcb81673b04d72dfe8704506af1872df637e1b830a5 }


condition:
	$a0
}