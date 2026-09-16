rule Win_Trojan_V_62
{
strings:
	$a0 = { f3a4061fbaf101b82125cd210e1f89ebc33d004b74 }


condition:
	$a0
}