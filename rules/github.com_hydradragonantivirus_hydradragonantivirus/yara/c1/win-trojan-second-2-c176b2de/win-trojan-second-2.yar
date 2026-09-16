rule Win_Trojan_Second_2
{
strings:
	$a0 = { 40b9b702cd21b9ffff5b2b4f0a81e9bb02894f0a8bd383 }


condition:
	$a0
}