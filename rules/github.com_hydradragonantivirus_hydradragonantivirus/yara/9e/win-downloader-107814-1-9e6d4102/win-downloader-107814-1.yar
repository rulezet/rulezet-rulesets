rule Win_Downloader_107814_1
{
strings:
	$a0 = { 33c003c08bc291915152e80dceffffc38ea417e5c581be6ffb11f60801398187cb3fe44676 }


condition:
	$a0
}