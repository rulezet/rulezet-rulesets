rule Win_Trojan_SillyRC_37
{
strings:
	$a0 = { 4a2e813ebf015058744133d233c9b80242cd2172360bd275328bf8b9c101b80040cd21722633d2 }


condition:
	$a0
}