rule Win_Trojan_CivilWar_2
{
strings:
	$a0 = { 7d01b440b97e008d960401cd21b8004233c999cd21b440b903008d967c01cd21b43ecd21b44f }


condition:
	$a0
}