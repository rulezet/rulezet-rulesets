rule Win_Downloader_Small_3214
{
strings:
	$a0 = { 9a3a1753fc80c8512058afea9a3814562586aeeaba3810ff8e2f7cff6dcf92fce73186e29ee5743f4f3325e0fa35a3b788d071e5cbbd098d94d9ad3945397070477234834b9b }


condition:
	$a0
}