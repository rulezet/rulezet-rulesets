rule Win_Trojan_HIV_1
{
strings:
	$a0 = { c31bd17204290606008bf733ff0e1f }


condition:
	$a0
}