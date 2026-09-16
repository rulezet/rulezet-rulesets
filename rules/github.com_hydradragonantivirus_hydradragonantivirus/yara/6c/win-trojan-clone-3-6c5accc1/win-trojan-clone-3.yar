rule Win_Trojan_Clone_3
{
strings:
	$a0 = { 7220b800405033d2b95601cd215880c40233c933d2cd21b80040ba5201b90400cd21b43ecd }


condition:
	$a0
}