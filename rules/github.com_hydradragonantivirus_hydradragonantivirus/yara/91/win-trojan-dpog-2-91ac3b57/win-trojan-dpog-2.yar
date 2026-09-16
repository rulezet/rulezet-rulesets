rule Win_Trojan_DPOG_2
{
strings:
	$a0 = { 4d462e2057686f20656c7365203f203b2d29299a00003c005589e581ec0001bf96000e57bf5200 }


condition:
	$a0
}