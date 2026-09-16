rule Win_Trojan_Gobot_9
{
strings:
	$a0 = { 59ffd1b802faba455932dbcd16b82435cd218c06a610891ea810b82425baf002cd211e07fe064203b44e33c9 }


condition:
	$a0
}