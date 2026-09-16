rule Win_Downloader_Agent_32867
{
strings:
	$a0 = { 69eb2cbdbbfca5de45d557d1f610ab9ca1b683dcafdf80622c27b3e2b15eab23f16bfb5ef5a4759880d6b0984614ccdc2da257b1759c051cf3daacf49572 }


condition:
	$a0
}