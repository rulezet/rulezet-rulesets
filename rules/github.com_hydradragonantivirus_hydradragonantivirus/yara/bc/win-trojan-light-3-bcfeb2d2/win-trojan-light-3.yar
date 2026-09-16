rule Win_Trojan_Light_3
{
strings:
	$a0 = { b9f203cdd72689551526895517c3065357e894002ef6 }


condition:
	$a0
}