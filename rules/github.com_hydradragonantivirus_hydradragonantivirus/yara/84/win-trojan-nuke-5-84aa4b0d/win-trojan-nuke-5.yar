rule Win_Trojan_Nuke_5
{
strings:
	$a0 = { 1e57b80c00509a77022800c6064d0001eb04fe064d00b88200509a64042800057d008ad0a0 }


condition:
	$a0
}