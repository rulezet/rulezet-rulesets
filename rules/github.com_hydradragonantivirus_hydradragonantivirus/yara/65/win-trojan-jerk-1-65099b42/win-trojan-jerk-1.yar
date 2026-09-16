rule Win_Trojan_Jerk_1
{
strings:
	$a0 = { 7f32c0f2ae263805e0f98bd783c2038c }


condition:
	$a0
}