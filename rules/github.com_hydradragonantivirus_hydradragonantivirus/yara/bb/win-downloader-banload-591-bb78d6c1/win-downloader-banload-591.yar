rule Win_Downloader_Banload_591
{
strings:
	$a0 = { 7f40940bb6f05a33fbb44b2e7803de591fea6d4ef08dfbfc22d6b61262562c106331c0da066c473389a96320c7f9a477a66dd8b2c1aa90f2a70d2454be5865dbabe6bb10 }


condition:
	$a0
}