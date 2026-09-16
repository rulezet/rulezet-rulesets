rule Win_Trojan_Onlinegames_41
{
strings:
	$a0 = { 558bec83ec4456ff15bf7b43008bf08a003c227513468a0684c074043c2275f5 }


condition:
	$a0
}