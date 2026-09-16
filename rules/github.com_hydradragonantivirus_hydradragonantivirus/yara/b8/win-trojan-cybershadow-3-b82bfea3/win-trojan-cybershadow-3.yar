rule Win_Trojan_CyberShadow_3
{
strings:
	$a0 = { 565753558bf7bf30f2b95c03e850005d5b5f5eb440cd21b000e83a008bd68bcdb440cd21595ab8 }


condition:
	$a0
}