rule Win_Trojan_Killav_145
{
strings:
	$a0 = { 406563686f206f6666 }

	$a1 = { 2f66202f696d206b61766d6d2e657865 }

	$a2 = { 202f66202f696d206b617670662e657865 }


condition:
	$a0 and $a1 and $a2
}