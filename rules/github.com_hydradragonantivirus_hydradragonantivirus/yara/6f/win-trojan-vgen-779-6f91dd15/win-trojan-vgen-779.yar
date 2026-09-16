rule Win_Trojan_VGEN_779
{
strings:
	$a0 = { da009a000078005589e531c09a5602da009ac0017800bf58021e57bf00000e5731c0509a8e06da009abf05da00 }


condition:
	$a0
}