rule Win_Trojan_Li_2
{
strings:
	$a0 = { 0301b43fbbb0fecd2181fb12127503e9e100bbffffb44a0e07cd2183eb6fb44a0e07cd21b452cd21268b47fe8e }


condition:
	$a0
}