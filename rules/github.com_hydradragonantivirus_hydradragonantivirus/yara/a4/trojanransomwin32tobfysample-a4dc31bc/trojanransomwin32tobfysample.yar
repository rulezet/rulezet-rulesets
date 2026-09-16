rule TrojanRansomWin32TobfySample
{
 	meta:
 		Description  = "Trojan.Tobfy.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://62.109.28.231/gtx3d16bv3/upload/img.jpg" ascii wide
		$ = "http://62.109.28.231/gtx3d16bv3/upload/mp3.mp3" ascii wide

		$ = "Pay MoneyPak" ascii wide
		$ = "You have 72 hours to pay the fine!" ascii wide
		$ = "Wait! Your request is processed within 24 hours." ascii wide
		$a = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\NEW Extern\\inject\\injc\\Release\\injc.pdb" ascii wide
		$b = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\Version V 1.0\\V1.0\\Release\\te.pdb" ascii wide
		$ = "picture.php?pin=" ascii wide
		$ = "s\\sound.mp3" ascii wide
		$ = "s\\1.jpg" ascii wide
		$ = "s\\1.bmp" ascii wide
		$ = "getunlock.php" ascii wide

 	condition:
 		(4 of them) or $a or $b
}