rule Win_Trojan_Ph33r_5
{
strings:
	$a0 = { ff51cd213d51ff74102adbcd168cd8488ed82bff803d }


condition:
	$a0
}