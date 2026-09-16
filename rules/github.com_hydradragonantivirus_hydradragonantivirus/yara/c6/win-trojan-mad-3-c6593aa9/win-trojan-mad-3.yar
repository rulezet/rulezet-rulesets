rule Win_Trojan_MAD_3
{
strings:
	$a0 = { 4fceb92ef6645df75f5ef4de5ea34dc79459a35dc65e5e13dfc37a5f0b1a22135850f55eae809859 }


condition:
	$a0
}