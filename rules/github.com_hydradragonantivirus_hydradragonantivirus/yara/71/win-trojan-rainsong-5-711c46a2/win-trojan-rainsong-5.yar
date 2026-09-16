rule Win_Trojan_RainSong_5
{
strings:
	$a0 = { 484e5aa223543962493d392508e3f2a0e27b40bda2fe96a196bf8160687b40bda2fe3f35e4e1f2a0c6f903a2141fb1708475b0c649743752ffbeb2 }


condition:
	$a0
}