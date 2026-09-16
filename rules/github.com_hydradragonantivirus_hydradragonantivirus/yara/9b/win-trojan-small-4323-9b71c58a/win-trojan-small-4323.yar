rule Win_Trojan_Small_4323
{
strings:
	$a0 = { 56575355e8[0-255]31c0034424486631c0505be90500 }


condition:
	$a0
}