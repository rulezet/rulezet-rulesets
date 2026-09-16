rule Win_Trojan_Gobot_3
{
strings:
	$a0 = { 1d095659ffd1b802faba455932dbcd16b82435cd218c063109891e3309b82425bad502cd211e07fe062707b44e33c9 }


condition:
	$a0
}