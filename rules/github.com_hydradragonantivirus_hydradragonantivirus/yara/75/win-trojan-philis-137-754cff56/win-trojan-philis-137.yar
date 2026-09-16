rule Win_Trojan_Philis_137
{
strings:
	$a0 = { 56be1600aa2481c6ba473f002bd65e52 }


condition:
	$a0
}