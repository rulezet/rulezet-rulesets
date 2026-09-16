rule Win_Trojan_Swiss_3
{
strings:
	$a0 = { 2993b43fb18f8bd6cd21803c507417 }


condition:
	$a0
}