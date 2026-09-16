rule Win_Downloader_Agent_35054
{
strings:
	$a0 = { 550fa14c4f1289f7a3f3f0b33e9e778b5b271936d20207efa72ac50a5e2a08b199f2b2f4446869cfa3234ae135f7088b7a6d }


condition:
	$a0
}