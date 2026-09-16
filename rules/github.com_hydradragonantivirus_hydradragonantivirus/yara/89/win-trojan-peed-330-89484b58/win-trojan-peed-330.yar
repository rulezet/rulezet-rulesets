rule Win_Trojan_Peed_330
{
strings:
	$a0 = { 81c14223bd00eb68ab5052516a0058a1088a400089c129c087d15050ffd24093 }


condition:
	$a0
}